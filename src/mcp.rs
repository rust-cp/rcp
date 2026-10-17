//! `rcp mcp`: a JSON-RPC 2.0 server on stdio, so an agent host can call rcp as a tool
//! instead of assembling a command line and parsing prose.
//!
//! Each tool call runs `rcp` itself as a child with `-json` and relays what it emitted.
//! Running the command in this process would be shorter by a page and wrong: the command
//! writes its events to stdout, which here is the protocol channel. A child keeps the two
//! apart, gives every call the same argument parsing and the same rails a person gets, and
//! means a copy that dies takes nothing with it.
//!
//! The rails are the point of the wiring rather than an afterthought. Whatever this server
//! was started with (`-allow`, `-readonly`, `-requireconfirm`, `RCP_ALLOWED_ROOTS`) is
//! passed to every child, and `-requireconfirm` is added whether or not it was asked for,
//! so a destructive call must carry the plan digest its own plan tool returned -- the dry
//! run of the same command, which is why `rcp_isync` has `rcp_isync_plan` beside it rather
//! than sharing `rcp_plan` with `rcp_copy`. An agent therefore cannot remove or overwrite
//! anything it has not first looked at.

use std::io::{self, BufRead, Write};
use std::os::unix::process::CommandExt;
use std::process::Command;

use crate::describe;
use crate::json::{self, quote, Json};

const PROTOCOL: &str = "2025-06-18";

extern "C" {
    fn prctl(option: i32, arg2: usize) -> i32;
    fn getppid() -> i32;
    fn _exit(status: i32) -> !;
}

const PR_SET_PDEATHSIG: i32 = 1;
const SIGTERM: i32 = 15;

/// Called only in the forked child's pre_exec callback, with the parent's pre-fork PID.
unsafe fn require_original_parent(expected_parent: i32) -> io::Result<()> {
    // SAFETY: prctl and getppid use integer arguments and retain no pointers. These
    // syscalls and _exit are async-signal-safe; the callback allocates no memory and
    // runs no Rust or C process-exit cleanup between fork and exec.
    unsafe {
        if prctl(PR_SET_PDEATHSIG, SIGTERM as usize) != 0 {
            return Err(io::Error::last_os_error());
        }
        // Reparenting may be to a container subreaper rather than PID 1.
        if getppid() != expected_parent {
            _exit(1);
        }
    }
    Ok(())
}

/// A tool: the name an agent calls, what it does, the rcp command it runs, and the
/// arguments it accepts. `takes` names the positional endpoints in order.
struct Tool {
    name: &'static str,
    summary: &'static str,
    command: &'static [&'static str],
    takes: &'static [&'static str],
    /// A call that could remove or overwrite, so it must carry `confirm`.
    destructive: bool,
    /// The tool whose digest this one takes. A destructive tool needs one, and it has to
    /// be the dry run of the SAME command: `rcp_plan` runs `copy -dryrun`, whose plan
    /// lists every source file, while `isync` lists only what differs and what it would
    /// remove. Pointing `rcp_isync` at `rcp_plan` -- which is what this said until the
    /// digests were compared -- asks an agent for a number that command can never print.
    plan: Option<&'static str>,
}

const TOOLS: &[Tool] = &[
    Tool { name: "rcp_plan", summary: "What a copy would do, without writing anything: one line per planned action and the plan digest that rcp_copy needs. Run this before any copy onto an existing tree.", command: &["copy", "-noId", "-dryrun"], takes: &["source", "destination"], destructive: false, plan: None },
    Tool { name: "rcp_copy", summary: "Copies a tree from source to destination. Into empty space this just runs; a copy that would overwrite anything is refused until `confirm` carries the plan digest from rcp_plan.", command: &["copy", "-noId"], takes: &["source", "destination"], destructive: true, plan: Some("rcp_plan") },
    Tool { name: "rcp_isync_plan", summary: "What rcp_isync would do, without writing anything: what it would copy, what it would remove, and the plan digest rcp_isync needs. Not the same plan as rcp_plan, which describes a copy.", command: &["isync", "-noId", "-dryrun"], takes: &["source", "destination"], destructive: false, plan: None },
    Tool { name: "rcp_isync", summary: "Brings destination in line with source, copying what changed and removing what the source dropped. Refused until `confirm` carries the plan digest from rcp_isync_plan.", command: &["isync", "-noId"], takes: &["source", "destination"], destructive: true, plan: Some("rcp_isync_plan") },
    Tool { name: "rcp_verify", summary: "Compares two trees byte for byte and reports every difference. Writes nothing.", command: &["verify"], takes: &["source", "destination"], destructive: false, plan: None },
    Tool { name: "rcp_scan", summary: "Lists a tree and reports its shape. Pass the option -l for an entry per item. Writes nothing.", command: &["scan"], takes: &["source"], destructive: false, plan: None },
    Tool { name: "rcp_count", summary: "What rcp_delete would remove, and the plan digest it needs. Removes nothing.", command: &["delete"], takes: &["target"], destructive: false, plan: None },
    Tool { name: "rcp_delete", summary: "Removes a tree. Refused until `confirm` carries the plan digest from rcp_count.", command: &["delete", "-force"], takes: &["target"], destructive: true, plan: Some("rcp_count") },
    Tool { name: "rcp_show", summary: "The mounted filesystems here, or what an NFS server offers when given a host.", command: &["show"], takes: &["host"], destructive: false, plan: None },
    Tool { name: "rcp_describe", summary: "Every command, option and endpoint scheme this build supports, with a capability table per scheme: whether it carries sparse files, hard links, symlinks, extended attributes, ACLs, identity and delta transfer, and how fine its times are.", command: &["describe"], takes: &[], destructive: false, plan: None },
];

fn tool(name: &str) -> Option<&'static Tool> {
    TOOLS.iter().find(|t| t.name == name)
}

/// The JSON schema of a tool's arguments: its endpoints, the option list, and `confirm`
/// where one is needed.
fn schema(t: &Tool) -> String {
    let mut props = Vec::new();
    for p in t.takes {
        let what = match *p {
            "source" => "The endpoint to read: a path, host:/export, nfs://, s3://, hdfs://, ssh://, sftp:// or oci://.",
            "destination" => "The endpoint to write: the same forms as source.",
            "target" => "The endpoint to act on.",
            "host" => "A host to ask, or omitted for the mounts here.",
            _ => "An endpoint.",
        };
        props.push(format!(
            "{}: {{\"type\": \"string\", \"description\": {}}}",
            quote(p),
            quote(what)
        ));
    }
    props.push(format!(
        "\"options\": {{\"type\": \"array\", \"items\": {{\"type\": \"string\"}}, \"description\": {}}}",
        quote("Extra rcp options, each written as it would be on the command line (\"-parallel\", \"8\", \"-exclude\", \"*.tmp\"). Only option names this build knows are accepted; call rcp_describe for the list.")
    ));
    if t.destructive {
        props.push(format!("\"confirm\": {{\"type\": \"string\", \"description\": {}}}", quote(&format!("The plan digest from {} for exactly this call, which has to be the same endpoints and the same options. Without it the call is refused, and a tree that changed since the plan was made no longer matches.", t.plan.unwrap_or("the matching plan tool")))));
    }
    let required: Vec<String> = t
        .takes
        .iter()
        .filter(|p| **p != "host")
        .map(|p| quote(p))
        .collect();
    format!(
        "{{\"type\": \"object\", \"properties\": {{{}}}, \"required\": [{}]}}",
        props.join(", "),
        required.join(", ")
    )
}

/// An option list from a caller, checked against the parser's own tables before it can
/// reach a command line. Anything else, an endpoint smuggled in as an option among them,
/// or a repeated `-confirm`, is refused here rather than passed on.
fn check_options(
    given: &[String],
    valued: &[&str],
    switches: &[&str],
) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < given.len() {
        let name = given[i].strip_prefix('-').ok_or_else(|| {
            format!(
                "{:?} is not an option; endpoints go in their own fields",
                given[i]
            )
        })?;
        let name = name.trim_start_matches('-');
        // Checking the NAME is not enough: the value is the capability. `-copybatch` is a
        // known option whose value is a program, and a call carrying
        // `-copybatch 'touch /tmp/x'` created that file while two `-allow` roots were in
        // force. What a call may set is decided by the classification every option carries
        // in `describe`, which a test requires to be complete -- so an option added later
        // is refused here until somebody classifies it, rather than exposed until somebody
        // remembers this file.
        match describe::capability_of(name) {
            None => {
                return Err(format!(
                    "-{name} is not an option this build knows; call rcp_describe for the list"
                ))
            }
            Some(c) => {
                if let Some(why) = c.why_not() {
                    return Err(format!("-{name} {why}; the server takes that from where it was started, not from a call"));
                }
            }
        }
        if valued.contains(&name) {
            let value = given
                .get(i + 1)
                .ok_or_else(|| format!("-{name} takes a value"))?;
            out.push(format!("-{name}"));
            out.push(value.clone());
            i += 2;
        } else if switches.contains(&name) {
            out.push(format!("-{name}"));
            i += 1;
        } else {
            return Err(format!(
                "-{name} is not an option this build knows; call rcp_describe for the list"
            ));
        }
    }
    Ok(out)
}

/// The most of a run's events one reply carries. A scan of a hundred million files emits
/// an event each; a reply is one JSON string an agent has to hold whole, and a tool call
/// is the wrong shape for a firehose. Past the limit the middle is dropped rather than the
/// end: an agent needs the `done` event and the errors, and `rcp job` (or `-json` on a
/// command it runs itself) is how a run that large is meant to be read.
const MAX_EVENTS: usize = 4 << 20;

/// Everything under the limit, or the beginning, a line saying what was dropped, and the
/// last events -- which are where `done` and any final error live.
fn trim_events(text: &str) -> String {
    if text.len() <= MAX_EVENTS {
        return text.to_string();
    }
    let keep = MAX_EVENTS / 2;
    let head_end = text.as_bytes()[..keep]
        .iter()
        .rposition(|&b| b == b'\n')
        .map(|i| i + 1)
        .unwrap_or(0);
    let tail_start = text.len() - keep
        + text.as_bytes()[text.len() - keep..]
            .iter()
            .position(|&b| b == b'\n')
            .map(|i| i + 1)
            .unwrap_or(keep);
    let dropped = text[head_end..tail_start].lines().count();
    format!(
        "{}{{\"event\":\"warning\",\"message\":\"{dropped} events dropped from the middle of this reply: the run emitted more than {MAX_EVENTS} bytes of them. Run it as a job, or with -json, to read them all.\"}}\n{}",
        &text[..head_end],
        &text[tail_start..]
    )
}

/// What the server adds to every child: the rails it was started with, plus
/// `-requireconfirm`, so a destructive call cannot happen without a plan digest even when
/// nobody asked for that.
/// The environment variable a service or credential option is relayed through, if any.
///
/// The server relays these to the child through the ENVIRONMENT and not the command line,
/// because the command line cannot carry them. `rails` always injects `-requireconfirm`,
/// which makes the child a railed run; a railed run refuses `Service` and `Credential`
/// options on its command line, because it cannot tell an option the operator set from
/// one the caller wrote. So relaying `-oci.user` as an argument makes the child refuse the
/// very credential the server was started with:
///
/// ```text
/// $ rcp mcp -oci.insecure -oci.user operator:secret   # then rcp_scan an oci:// repo
/// -oci.user chooses or carries a credential, which no rail can bound
/// ```
///
/// The two rules are each correct and directly conflict, and a unit test that reads
/// `rails()` output without running a child cannot see it.
///
/// The environment is the right channel and not a workaround: it is exactly the split the
/// rails rest on. The command line is what a caller writes and an operator reads; the
/// environment is the server's, and a call cannot reach it.
pub fn relay_env(name: &str) -> Option<&'static str> {
    match name {
        "oci.user" => Some("RCP_OCI_USER"),
        // WebDAV and http: without these, a server started `rcp mcp -dav.user
        // operator:s3cret` relays NOTHING, so every call it serves reaches the collection
        // unauthenticated and the 401 comes back as the caller's problem.
        // `a_credential_option_is_relayed_or_it_is_unreachable` below is the control that
        // stops the next one being forgotten -- reading this list does not find a missing
        // entry; enumerating `describe`'s table against it does, which that arm does on
        // every run.
        "dav.user" => Some("RCP_DAV_USER"),
        "smb.user" => Some("RCP_SMB_USER"),
        // An operator who started the server insisting on signing must not have that
        // quietly dropped for every child it runs.
        "smb.sign" => Some("RCP_SMB_SIGN"),
        "http.user" => Some("RCP_HTTP_USER"),
        // The rcps:// identity. A server started with one and a child that never sees it
        // would dial a mutual-TLS serve with no certificate and be turned away at the
        // handshake, which reads as the far side being down.
        "tls.ca" => Some("RCP_TLS_CA"),
        "tls.cert" => Some("RCP_TLS_CERT"),
        "tls.key" => Some("RCP_TLS_KEY"),
        "tls.clientca" => Some("RCP_TLS_CLIENTCA"),
        "s3.endpoint" => Some("RCP_S3_ENDPOINT"),
        "s3.profile" => Some("RCP_S3_PROFILE"),
        "hdfs.namenode" => Some("RCP_HDFS_NAMENODE"),
        // The catalog is a rail, so it is never forwarded as an OPTION -- and without this
        // entry `rcp mcp -catalog DIR` reaches no child at all: each one falls through to
        // its environment and the operator's choice is lost.
        "catalog" => Some("RCP_CATALOG"),
        // The server's TRANSPORT CONFIGURATION, which is a `Setting` and so is otherwise
        // relayed nowhere at all -- `rcp mcp -oci.insecure` would reach no child, and a
        // plain-HTTP registry would be simply unreachable through the server. Running the
        // server shows it where reading it does not: the credential probe comes back
        // complaining about TLS instead.
        "oci.insecure" => Some("RCP_OCI_INSECURE"),
        "oci.noverify" => Some("RCP_OCI_NOVERIFY"),
        // `dav.insecure` is here and `dav.noverify` is NOT, and the difference is not a
        // judgement: `RCP_DAV_INSECURE` is read (main's transport setup) and there is no
        // `RCP_DAV_NOVERIFY` or `RCP_HTTP_NOVERIFY` to relay to. Relaying to a variable
        // nothing reads would look like a fix and be a no-op, which is the failure this
        // whole list is prone to. Those two stay unreachable through the server until a
        // reader exists.
        "dav.insecure" => Some("RCP_DAV_INSECURE"),
        "s3.insecure" => Some("RCP_S3_INSECURE"),
        "s3.noverify" => Some("RCP_S3_NOVERIFY"),
        // The NFS family, which only enumerating the option table rather than sampling it
        // finds. Without these, a server started `-nfs.sec krb5p` relays nothing, so every
        // call it serves speaks AUTH_SYS to an export that was meant to need Kerberos.
        "nfs.sec" => Some("RCP_NFS_SEC"),
        "nfs.vers" => Some("RCP_NFS_VERS"),
        "acl4" => Some("RCP_NFS_ACL4"),
        _ => None,
    }
}

/// The rails for a child, and the server settings relayed beside them.
///
/// Returns the arguments and the environment to add. A `Runs` option is in NEITHER: no
/// rail can bound what a program does, and a server running one on a caller's behalf is
/// the thing `-copybatch` was refused for in the first place.
fn rails(server_args: &[String], valued: &[&str]) -> (Vec<String>, Vec<(String, String)>) {
    let mut out = vec!["-requireconfirm".to_string()];
    let mut env = Vec::new();
    let mut i = 0;
    while i < server_args.len() {
        let name = server_args[i].trim_start_matches('-');
        let value = valued
            .contains(&name)
            .then(|| server_args.get(i + 1).cloned())
            .flatten();
        if valued.contains(&name) {
            i += 1;
        }
        i += 1;
        let Some(cap) = describe::capability_of(name) else {
            continue;
        };
        // A switch has no value; setting the variable at all is the switch.
        if let Some(var) = relay_env(name) {
            env.push((var.to_string(), value.unwrap_or_else(|| "1".to_string())));
            continue;
        }
        if cap.why_not().is_none() || name == "json" || name == "catalog" {
            continue;
        }
        if cap == describe::Capability::Runs {
            continue;
        }
        out.push(format!("-{name}"));
        if let Some(v) = value {
            out.push(v);
        }
    }
    (out, env)
}

fn field<'a>(args: &'a Json, key: &str) -> Option<&'a str> {
    args.get(key)
        .and_then(Json::as_str)
        .filter(|v| !v.is_empty())
}

fn endpoint_arg(value: &str) -> Result<String, String> {
    if value.starts_with('-') {
        return Err(
            "an endpoint cannot start with '-'; use './' for a local filename beginning with '-'"
                .into(),
        );
    }
    Ok(value.to_string())
}

fn strings(args: &Json, key: &str) -> Result<Vec<String>, String> {
    match args.get(key) {
        None | Some(Json::Null) => Ok(Vec::new()),
        Some(Json::Array(a)) => a
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| format!("{key} takes strings"))
            })
            .collect(),
        Some(_) => Err(format!("{key} takes an array of strings")),
    }
}

/// Runs one tool and returns what to put in the result's text.
fn run(
    name: &str,
    args: &Json,
    server_args: &[String],
    valued: &[&str],
    switches: &[&str],
) -> Result<String, String> {
    let t = tool(name).ok_or_else(|| format!("no tool named {name}"))?;
    let exe = std::env::current_exe().map_err(|e| format!("this program's own path: {e}"))?;
    let mut argv: Vec<String> = t.command.iter().map(|c| c.to_string()).collect();
    if name != "rcp_describe" {
        argv.insert(0, "-json".to_string());
    }
    // `confirm` is passed on when it is given and never demanded here: whether this call
    // would actually remove or overwrite anything is something only the plan knows, and
    // the child computes that. A copy into empty space therefore just runs, and a copy
    // over an existing tree is refused by the same rail a person would meet.
    if let Some(confirm) = field(args, "confirm") {
        argv.push("-confirm".into());
        argv.push(confirm.to_string());
    }
    let (rail_args, rail_env) = rails(server_args, valued);
    argv.extend(rail_args);
    let caller_opts = check_options(&strings(args, "options")?, valued, switches)?;
    if !t.destructive && caller_opts.iter().any(|a| a == "-force") {
        return Err(format!(
            "{name} does not delete; -force is refused on it. rcp_delete is the tool that removes a tree"
        ));
    }
    argv.extend(caller_opts);
    for p in t.takes {
        match field(args, p) {
            Some(v) => argv.push(endpoint_arg(v)?),
            None if *p == "host" => {}
            None => return Err(format!("{name} needs {p}")),
        }
    }
    let mut command = Command::new(exe);
    command.args(&argv);
    for (k, v) in rail_env {
        command.env(k, v);
    }
    // A child outliving this server is a copy or a delete nobody is watching: the host
    // that killed the server believes the call was canceled, and the run carries on. The
    // kernel sends the child SIGTERM when its parent dies, so canceling the call cancels
    // the work. `rcp job` is how a run is *meant* to outlive its caller, and it sets up
    // its own session precisely so this does not reach it.
    //
    // `PR_SET_PDEATHSIG` is bound to the calling THREAD, not to the process: the child is
    // signaled when the thread that forked it dies, healthy parent or not. That is safe
    // here only because this server has no threads -- it is one read-a-line, run-it,
    // write-a-line loop, so the forking thread is the process. It looks like a defect; it
    // is not one today, and it becomes one the moment a call is served off a worker
    // thread. Whoever adds that has to move this to a watchdog on the parent pid.
    let expected_parent = std::process::id() as i32;
    // SAFETY: the callback performs only the async-signal-safe operations described in
    // require_original_parent and captures a pre-fork integer, with no locks or cleanup.
    unsafe {
        command.pre_exec(move || require_original_parent(expected_parent));
    }
    let out = command.output().map_err(|e| format!("running rcp: {e}"))?;
    let stdout = trim_events(&String::from_utf8_lossy(&out.stdout));
    let stderr = String::from_utf8_lossy(&out.stderr);
    // the events are the answer; the human lines are on stderr and only the failing ones
    // are worth carrying, since an agent that wanted prose would not be calling a tool
    if out.status.success() {
        return Ok(stdout);
    }
    let mut why: Vec<String> = stderr
        .lines()
        .filter(|l| l.starts_with("ERROR:") || l.starts_with("WARN:"))
        .map(str::to_string)
        .collect();
    // the rail's own words name a command-line option; an agent needs the tool to call
    if why.iter().any(|l| l.contains("-confirm")) {
        // the tool's OWN plan tool: a copy's plan and an isync's plan are different lists
        // and hash differently, so naming the wrong one sends an agent after a digest the
        // command it called can never be given
        if let Some(plan) = tool(name).and_then(|t| t.plan) {
            why.push(format!("Call {plan} with the same endpoints and options, read what it would do, and pass the digest it returns as `confirm`."));
        }
    }
    Err(if stdout.trim().is_empty() {
        why.join("\n")
    } else {
        format!("{}\n{}", stdout.trim_end(), why.join("\n"))
    })
}

fn reply(id: &str, result: &str) -> String {
    format!("{{\"jsonrpc\": \"2.0\", \"id\": {id}, \"result\": {result}}}")
}

fn error(id: &str, code: i32, message: &str) -> String {
    format!(
        "{{\"jsonrpc\": \"2.0\", \"id\": {id}, \"error\": {{\"code\": {code}, \"message\": {}}}}}",
        quote(message)
    )
}

/// The content of a tool result: one text block, with `isError` when the call failed, which
/// is how MCP says "the tool ran and refused" as opposed to "the call was malformed".
fn content(text: &str, failed: bool) -> String {
    format!(
        "{{\"content\": [{{\"type\": \"text\", \"text\": {}}}], \"isError\": {failed}}}",
        quote(text)
    )
}

/// The top-level request's `id`, so a number stays a number and a string stays a
/// string when it goes back. An id this server cannot echo is not one it should answer.
fn id_of(doc: &Json) -> Option<String> {
    match doc.get("id")? {
        Json::Str(s) => Some(quote(s)),
        Json::Number(n) => Some(n.clone()),
        Json::Null => Some("null".into()),
        _ => None,
    }
}

/// Serves JSON-RPC on stdio until the input ends: one message per line, replies in order.
/// `server_args` are this server's own arguments, whose rails every call inherits.
pub fn serve(server_args: &[String], valued: &[&str], switches: &[&str]) -> io::Result<()> {
    let stdin = io::stdin();
    let mut out = io::stdout();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let doc = match json::parse(line.as_bytes()) {
            Ok(d) => d,
            Err(e) => {
                writeln!(
                    out,
                    "{}",
                    error("null", -32700, &format!("the message is not JSON: {e}"))
                )?;
                out.flush()?;
                continue;
            }
        };
        let method = doc.get("method").and_then(Json::as_str).unwrap_or("");
        let id = id_of(&doc);
        // a notification carries no id and takes no reply, which includes the
        // `notifications/initialized` every host sends after the handshake
        let Some(id) = id else {
            continue;
        };
        let answer = match method {
            "initialize" => reply(
                &id,
                &format!(
                    "{{\"protocolVersion\": {}, \"capabilities\": {{\"tools\": {{}}}}, \"serverInfo\": {{\"name\": \"rcp\", \"version\": {}}}}}",
                    quote(PROTOCOL),
                    quote(env!("CARGO_PKG_VERSION"))
                ),
            ),
            "ping" => reply(&id, "{}"),
            "tools/list" => {
                let tools: Vec<String> = TOOLS.iter().map(|t| format!("{{\"name\": {}, \"description\": {}, \"inputSchema\": {}}}", quote(t.name), quote(t.summary), schema(t))).collect();
                reply(&id, &format!("{{\"tools\": [{}]}}", tools.join(", ")))
            }
            "tools/call" => {
                let params = doc.get("params");
                let name = params.and_then(|p| p.get("name")).and_then(Json::as_str).unwrap_or("");
                match tool(name) {
                    None => error(&id, -32602, &format!("no tool named {name:?}; call tools/list for the ones there are")),
                    Some(_) => {
                        let empty = Json::Object(Default::default());
                        let args = params.and_then(|p| p.get("arguments")).unwrap_or(&empty);
                        match run(name, args, server_args, valued, switches) {
                            Ok(text) => reply(&id, &content(&text, false)),
                            Err(text) => reply(&id, &content(&text, true)),
                        }
                    }
                }
            }
            "resources/list" => reply(&id, "{\"resources\": []}"),
            "prompts/list" => reply(&id, "{\"prompts\": []}"),
            other => error(&id, -32601, &format!("this server has no method {other:?}; it serves initialize, ping, tools/list and tools/call")),
        };
        writeln!(out, "{answer}")?;
        out.flush()?;
    }
    Ok(())
}

/// The tool names, for a caller that wants to check the surface without speaking the
/// protocol (and for the arms that do exactly that).
pub fn tool_names() -> Vec<&'static str> {
    TOOLS.iter().map(|t| t.name).collect()
}

/// Whether a tool is one that can remove or overwrite, and so needs a plan digest.
pub fn is_destructive(name: &str) -> bool {
    tool(name).is_some_and(|t| t.destructive)
}

/// Every command a tool runs is one `rcp describe` publishes; nothing here invents a
/// command name of its own.
pub fn commands_used() -> Vec<&'static str> {
    TOOLS.iter().map(|t| t.command[0]).collect()
}

/// Each destructive tool with the tool whose digest it takes, and the command each runs.
/// A pair whose commands differ by more than `-dryrun` cannot agree on a digest, because
/// the digest is a hash over the planned action lines and a copy's plan is not an isync's.
pub fn plan_pairs() -> Vec<(
    &'static str,
    Option<&'static str>,
    Vec<&'static str>,
    Vec<&'static str>,
)> {
    TOOLS
        .iter()
        .filter(|t| t.destructive)
        .map(|t| {
            (
                t.name,
                t.plan,
                t.command.to_vec(),
                t.plan
                    .and_then(tool)
                    .map(|p| p.command.to_vec())
                    .unwrap_or_default(),
            )
        })
        .collect()
}

/// The commands this server will run that `describe` marks as writing.
pub fn writing_commands() -> Vec<&'static str> {
    commands_used()
        .into_iter()
        .filter(|c| describe::COMMANDS.iter().any(|d| d.name == *c && d.writes))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_child_executes_only_while_its_original_parent_is_present() {
        for (expected_parent, expected_exit) in [(std::process::id() as i32, 42), (-1, 1)] {
            let mut command = Command::new("/bin/sh");
            command.args(["-c", "exit 42"]);
            // SAFETY: this uses the production post-fork callback, which only performs
            // async-signal-safe syscalls. No signal targets another process in this test.
            unsafe {
                command.pre_exec(move || require_original_parent(expected_parent));
            }
            assert_eq!(command.status().unwrap().code(), Some(expected_exit));
        }
    }

    #[test]
    fn endpoints_cannot_inject_command_line_options() {
        for value in ["-allow", "--allow", "-oci.noverify", "-copybatch", "-"] {
            assert!(endpoint_arg(value).is_err(), "accepted {value}");
        }
        for value in ["./-allow", "/tmp/-allow", "s3://bucket/key"] {
            assert_eq!(endpoint_arg(value).unwrap(), value);
        }
    }

    const VALUED: &[&str] = &["parallel", "exclude", "confirm", "allow", "catalog"];
    const SWITCHES: &[&str] = &["l", "delta", "readonly", "json"];

    #[test]
    fn an_option_list_is_checked_against_the_parsers_tables() {
        assert_eq!(
            check_options(
                &["-parallel".into(), "8".into(), "-l".into()],
                VALUED,
                SWITCHES
            )
            .unwrap(),
            vec!["-parallel", "8", "-l"]
        );
        // an option this build does not know never reaches a command line
        assert!(check_options(&["-frobnicate".into()], VALUED, SWITCHES).is_err());
        // nor does an endpoint smuggled in among the options
        assert!(check_options(&["/etc/passwd".into()], VALUED, SWITCHES)
            .unwrap_err()
            .contains("endpoints go in their own fields"));
        // nor a value-taking option with nothing after it, which would swallow an endpoint
        assert!(check_options(&["-parallel".into()], VALUED, SWITCHES).is_err());
        // nor the options the server sets itself, whatever the caller says
        for name in [
            "-confirm",
            "-allow",
            "-readonly",
            "-requireconfirm",
            "-json",
            "-catalog",
        ] {
            assert!(
                check_options(&[name.to_string(), "x".into()], VALUED, SWITCHES).is_err(),
                "{name} must not be settable by a call"
            );
        }
        // nor the options that weaken the connection. As `Setting`, the class a call MAY
        // set, a caller answering a railed server could send `options: ["-oci.noverify"]`
        // and turn certificate verification off for a host the operator named -- the rails
        // say where a run may go, and would say nothing about whether the wire to there
        // was worth anything.
        // Every `Transport` there is, read from the table rather than typed: a typed list
        // of the four TLS names stays green when `-nfs.sec` is planted back to `Setting`. A
        // list of names is a second copy of the classification, and the second copy is the
        // one that goes stale.
        let transports: Vec<&str> = describe::OPTIONS
            .iter()
            .filter(|(_, c, _)| *c == describe::Capability::Transport)
            .map(|(n, _, _)| *n)
            .collect();
        assert!(
            transports.len() >= 6,
            "the table lost its Transport options: {transports:?}"
        );
        for name in &transports {
            let valued: &[&str] = &["nfs.sec", "nfs.vers"];
            let refused =
                check_options(&[format!("-{name}"), "x".into()], valued, &transports).unwrap_err();
            assert!(
                refused.contains("weakens how the connection is made"),
                "-{name}: {refused}"
            );
        }
        // the control on that: a plain setting of the same shape is still accepted, or the
        // refusal above would only be measuring that switches are refused
        assert_eq!(
            check_options(&["-l".into()], VALUED, SWITCHES).unwrap(),
            vec!["-l"]
        );
    }

    #[test]
    fn every_call_carries_the_rails_the_server_was_started_with() {
        let valued: &[&str] = &["allow", "oci.user", "parallel", "s3.endpoint"];
        let (r, env) = rails(
            &["-allow".into(), "/data".into(), "-readonly".into()],
            valued,
        );
        assert!(
            r.contains(&"-requireconfirm".to_string()),
            "a destructive call must need a digest even when nobody asked"
        );
        assert_eq!(r.iter().filter(|a| *a == "-allow").count(), 1);
        assert!(r.contains(&"/data".to_string()));
        assert!(r.contains(&"-readonly".to_string()));
        assert!(
            env.is_empty(),
            "a rail belongs on the command line, where an operator reads it: {env:?}"
        );
        // with no rails at all, the confirmation one is still added
        assert_eq!(rails(&[], valued).0, vec!["-requireconfirm"]);

        // A credential the server was started with reaches its children through the
        // ENVIRONMENT, and putting it on the command line was a defect of this same
        // session: `rails` always adds `-requireconfirm`, which makes the child a railed
        // run, and a railed run refuses a credential on its command line because it cannot
        // tell one the operator set from one the caller wrote. So the relay made the child
        // refuse the server's own credential. Measured end to end, and that end-to-end arm
        // is in the contract suite -- this one reads the relay, which is exactly how the
        // conflict went unnoticed.
        let (r, env) = rails(&["-oci.user".into(), "someone:secret".into()], valued);
        assert_eq!(
            r,
            vec!["-requireconfirm"],
            "a credential on the command line is refused by the child: {r:?}"
        );
        assert_eq!(
            env,
            vec![("RCP_OCI_USER".to_string(), "someone:secret".to_string())]
        );
        // the same for a service, and for the transport configuration, which as a plain
        // setting was relayed NOWHERE before -- `rcp mcp -oci.insecure` reached no child
        let (_, env) = rails(&["-s3.endpoint".into(), "http://minio:9000".into()], valued);
        assert_eq!(
            env,
            vec![(
                "RCP_S3_ENDPOINT".to_string(),
                "http://minio:9000".to_string()
            )]
        );
        let (r, env) = rails(&["-oci.insecure".into()], valued);
        assert_eq!(r, vec!["-requireconfirm"]);
        assert_eq!(env, vec![("RCP_OCI_INSECURE".to_string(), "1".to_string())]);
        // something to run is relayed NEITHER way: no rail can bound what a program does,
        // and a server running one for a caller is what `-copybatch` was refused for
        let (r, env) = rails(
            &["-copybatch".into(), "touch /tmp/x".into()],
            &["copybatch"],
        );
        assert_eq!(r, vec!["-requireconfirm"], "{r:?}");
        assert!(env.is_empty(), "{env:?}");
        // a plain setting is not relayed: a call may set that itself, and the server has
        // no business fixing it for every call
        let (r, env) = rails(&["-parallel".into(), "4".into()], valued);
        assert_eq!(r, vec!["-requireconfirm"], "{r:?}");
        assert!(env.is_empty(), "{env:?}");
    }

    #[test]
    fn ids_go_back_as_they_came() {
        let parsed_id = |line: &str| id_of(&json::parse(line.as_bytes()).unwrap());
        assert_eq!(
            parsed_id(r#"{"jsonrpc":"2.0","id":7,"method":"ping"}"#).as_deref(),
            Some("7")
        );
        assert_eq!(
            parsed_id(r#"{"jsonrpc":"2.0","id":"a-1","method":"ping"}"#).as_deref(),
            Some("\"a-1\"")
        );
        assert_eq!(
            parsed_id(r#"{"jsonrpc":"2.0","id":-3,"method":"ping"}"#).as_deref(),
            Some("-3")
        );
        // a notification has none, and gets no reply
        assert_eq!(
            parsed_id(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#),
            None
        );
    }

    #[test]
    fn request_ids_use_the_top_level_field_and_escape_strings() {
        for input in [
            r#"{"params":{"id":99},"id":"a\"b\\c\n","method":"ping"}"#,
            r#"{"\u0069d":"a\"b\\c\n","method":"ping"}"#,
        ] {
            let doc = json::parse(input.as_bytes()).unwrap();
            let id = id_of(&doc).unwrap();
            let response = json::parse(reply(&id, "{}").as_bytes()).unwrap();
            assert_eq!(response.get("id"), doc.get("id"));
        }
        let notification = json::parse(br#"{"params":{"id":99},"method":"ping"}"#).unwrap();
        assert_eq!(id_of(&notification), None);
    }

    #[test]
    fn trimming_events_handles_unicode_at_both_cutoffs() {
        let keep = MAX_EVENTS / 2;
        // Each cutoff lands inside the UTF-8 encoding of an accented character.
        let text = format!(
            "{}é\n{}\né{}",
            "a".repeat(keep - 1),
            "b".repeat(32),
            "c".repeat(keep - 1)
        );
        assert!(!text.is_char_boundary(keep));
        assert!(!text.is_char_boundary(text.len() - keep));
        let trimmed = trim_events(&text);
        assert!(trimmed.contains("events dropped from the middle"));
        for line in trimmed.lines() {
            assert!(json::parse(line.as_bytes()).is_ok());
        }
        assert_eq!(trim_events("é\n"), "é\n");
    }

    #[test]
    fn the_schemas_say_what_each_tool_needs() {
        for t in TOOLS {
            let s = schema(t);
            assert!(s.contains("\"options\""), "{} takes no options", t.name);
            assert_eq!(
                s.contains("\"confirm\""),
                t.destructive,
                "{} and confirm disagree",
                t.name
            );
            for p in t.takes {
                assert!(s.contains(&quote(p)), "{} does not name {p}", t.name);
            }
            // `host` is the one endpoint that may be left out, so it is never required
            assert!(!s.contains("\"required\": [\"host\"]"));
        }
        assert!(is_destructive("rcp_delete"));
        assert!(is_destructive("rcp_copy"));
        assert!(!is_destructive("rcp_plan"));
        assert!(!is_destructive("rcp_verify"));
        assert!(!is_destructive("rcp_count"));
    }
}

#[cfg(test)]
mod trim_tests {
    use super::*;

    #[test]
    fn a_reply_too_large_to_hold_keeps_its_ends_and_says_what_it_dropped() {
        let small = "{\"event\":\"entry\",\"path\":\"a\"}\n{\"event\":\"done\"}\n";
        assert_eq!(
            trim_events(small),
            small,
            "a reply under the limit is untouched"
        );

        let mut big = String::new();
        let mut n = 0;
        while big.len() < MAX_EVENTS * 2 {
            big.push_str(&format!(
                "{{\"event\":\"entry\",\"path\":\"file-{n:09}\"}}\n"
            ));
            n += 1;
        }
        big.push_str("{\"event\":\"done\",\"status\":\"passed\"}\n");
        let out = trim_events(&big);
        assert!(
            out.len() < big.len() && out.len() <= MAX_EVENTS + 4096,
            "{} bytes",
            out.len()
        );
        assert!(
            out.starts_with("{\"event\":\"entry\",\"path\":\"file-000000000\"}"),
            "the beginning is kept"
        );
        assert!(
            out.trim_end()
                .ends_with("{\"event\":\"done\",\"status\":\"passed\"}"),
            "the done event is kept"
        );
        assert!(
            out.contains("events dropped from the middle"),
            "the drop is stated, not silent"
        );
        // every line is still a whole JSON object: a truncated one would break the reader
        for line in out.lines() {
            assert!(
                line.starts_with('{') && line.ends_with('}'),
                "half a line survived: {line}"
            );
        }
    }

    /// `rcp mcp -catalog DIR` must reach every child. `rails` skips the name as a rail, so
    /// without a `relay_env` row every child falls through to `RCP_CATALOG` or the default
    /// and the operator's choice is lost -- the opposite of what the README promises.
    #[test]
    fn the_catalog_the_server_was_started_with_reaches_every_child() {
        const VALUED: &[&str] = &["parallel", "exclude", "confirm", "allow", "catalog"];
        let (r, env) = rails(&["-catalog".into(), "/custom/catalog".into()], VALUED);
        assert!(
            !r.contains(&"-catalog".to_string()),
            "a rail is not forwarded as an option: {r:?}"
        );
        assert_eq!(
            env,
            vec![("RCP_CATALOG".to_string(), "/custom/catalog".to_string())],
            "the catalog did not reach the child"
        );
    }

    /// `relay_env` is a hand-kept list against a table that grows, and it has now been
    /// wrong three times in the same way: an option the server accepts reaches no child,
    /// so the server takes the setting and every call it serves ignores it. `oci.insecure`
    /// was found by running the server; `dav.user` and `http.user` by enumerating the
    /// table against the list. This arm does that enumeration on every run.
    ///
    /// Credentials only. The other capabilities have real reasons not to relay -- a `Runs`
    /// option is refused outright, and `dav.noverify` has no variable to relay TO -- but a
    /// credential the server was started with and the child never sees is never a choice.
    #[test]
    fn a_credential_option_is_relayed_or_it_is_unreachable() {
        let missing: Vec<&str> = describe::OPTIONS
            .iter()
            .filter(|(_, cap, _)| *cap == describe::Capability::Credential)
            .map(|(name, _, _)| *name)
            .filter(|name| relay_env(name).is_none())
            .collect();
        assert!(missing.is_empty(), "these credential options reach no child, so a server started with one serves calls without it: {missing:?}");
        // and the list is not empty, which is what makes the assertion above mean anything
        let n = describe::OPTIONS
            .iter()
            .filter(|(_, cap, _)| *cap == describe::Capability::Credential)
            .count();
        assert!(
            n >= 4,
            "the credential table has shrunk to {n}; the arm above would pass on an empty one"
        );

        // The control: `relay_env` answers `None` for something, so it is a filter rather
        // than a function that says yes. `mode` is a plain `Setting` and forwards as an
        // option, on the command line where an operator can read it.
        assert!(
            relay_env("mode").is_none(),
            "relay_env says yes to everything, so the arm above proves nothing"
        );
        // and every variable it does name is one the source actually reads -- relaying to
        // a name nothing reads looks like a fix and is a no-op
        let src = include_str!("dav/client.rs");
        assert!(
            src.contains("RCP_DAV_USER"),
            "dav.user is relayed to a variable the WebDAV client does not read"
        );
    }
}
