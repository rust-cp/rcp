//! `rcp describe`: what this build can do, as one JSON object, so a caller that is a
//! program does not have to parse the usage text or be told out of band.
//!
//! The option list is built from the very arrays the argument parser matches against, so
//! an option cannot exist without appearing here; what this module adds is a summary per
//! option, and `tests/describe.rs` fails when one is missing. That is a stronger guarantee
//! than agreeing with the prose: the prose can drift from the parser, this cannot.

use crate::json::quote;

/// A command and the positional arguments it takes.
pub struct Command {
    pub name: &'static str,
    pub takes: &'static str,
    pub summary: &'static str,
    /// Whether it writes to the destination endpoint.
    pub writes: bool,
}

pub const COMMANDS: &[Command] = &[
    Command { name: "copy", takes: "SOURCE DESTINATION", summary: "copies a tree, recording every entry in a catalog", writes: true },
    Command { name: "resume", takes: "", summary: "finishes the copy of the catalog named by -id", writes: true },
    Command { name: "sync", takes: "", summary: "brings the destination of -id back in line with its source, removing what the source dropped", writes: true },
    Command { name: "isync", takes: "SOURCE DESTINATION", summary: "syncs without a catalog, comparing the two trees as they are", writes: true },
    Command { name: "verify", takes: "SOURCE DESTINATION", summary: "compares two trees byte for byte and reports every difference", writes: false },
    Command { name: "scan", takes: "SOURCE", summary: "lists a tree and reports its shape, optionally saving the listing as an index", writes: false },
    Command { name: "estimate", takes: "SOURCE", summary: "projects how long a copy would take, from a measured sample", writes: false },
    Command { name: "delete", takes: "TARGET", summary: "removes a tree; counts only until -force", writes: true },
    Command { name: "chmod", takes: "TARGET", summary: "applies a mode across a tree", writes: true },
    Command { name: "chown", takes: "TARGET", summary: "applies an owner and group across a tree", writes: true },
    Command { name: "diag", takes: "SUBCOMMAND", summary: "the diagnostic family: file utilities, generated I/O, index diagnosis, find and change", writes: true },
    Command { name: "show", takes: "[HOST]", summary: "the mounted filesystems here, or what an NFS server offers", writes: false },
    Command { name: "serve", takes: "", summary: "the far end of an ssh:// endpoint, on stdio; takes no arguments", writes: true },
    Command { name: "indexlist", takes: "", summary: "the catalogs under the catalog directory", writes: false },
    Command { name: "indexdelete", takes: "", summary: "removes the catalogs named by -id or -match", writes: true },
    Command { name: "logdump", takes: "", summary: "the job log; given an ID it also writes ID.zip in the working directory", writes: false },
    Command { name: "copybatch", takes: "", summary: "copies one batch of files on a worker's behalf (-nodes)", writes: true },
    Command { name: "scanbatch", takes: "", summary: "scans one subtree on a worker's behalf (-nodes)", writes: false },
    // the server writes nothing itself: a call runs rcp as a child, and that child
    // carries this server's rails, so -readonly starts the server and refuses the writes
    Command { name: "job", takes: "start|list|status|wait|cancel|log|forget", summary: "runs a command in a session of its own and reports on it afterwards, so a caller need not wait for a terabyte; a canceled job leaves its catalog behind, which `rcp resume` finishes for a copy -- a sweeping verb (`sync`, `isync`) is finished by running that verb again, because `resume` never plans a removal", writes: true },
    Command { name: "mcp", takes: "[rails]", summary: "a JSON-RPC 2.0 server on stdio, so an agent host can call rcp as a tool. The server writes nothing itself; each call runs rcp as a child, which carries this server's rails, so -readonly here makes every call read-only rather than refusing to start", writes: false },
    Command { name: "describe", takes: "", summary: "this description, as JSON", writes: false },
    Command { name: "help", takes: "[info|filters]", summary: "the usage text", writes: false },
    Command { name: "version", takes: "", summary: "the version, the transports and what this build's hardware offers", writes: false },
];

/// What an endpoint scheme can carry. Every field is a statement about the protocol, not
/// about a particular server: `false` means the protocol has no way to say it, so rcp
/// refuses or approximates it in the open.
pub struct Scheme {
    pub name: &'static str,
    pub syntax: &'static str,
    pub summary: &'static str,
    pub writable: bool,
    pub sparse: bool,
    pub hard_links: bool,
    pub symlinks: bool,
    pub xattrs: bool,
    pub acls: bool,
    pub rename: bool,
    /// Inode numbers, which is what lets `sync` tell a renamed file from a new one and
    /// `copy` keep a hard link.
    pub identity: bool,
    pub delta: bool,
    /// The finest modification time the protocol can carry AND HAND BACK. Three rows said
    /// something the adapter contradicts, and `dav` was the worst of them: "second" reads
    /// as "kept, coarsely", while a WebDAV server stamps its OWN write time and this crate
    /// cannot set it -- `keeps_times()` is false there. An agent caller reads this table
    /// first and has nothing else to check it against, so a wrong cell here is a wrong
    /// decision downstream. `tests/describe.rs` now asserts each value against the
    /// adapter's own `keeps_times()`, which is the only thing that makes the column true
    /// rather than decorative.
    ///
    /// "none" means the value in a listing from this scheme is not the entry's own.
    pub times: &'static str,
}

pub const SCHEMES: &[Scheme] = &[
    #[cfg(unix)]
    Scheme { name: "file", syntax: "/path or file:///path", summary: "a local or mounted directory", writable: true, sparse: true, hard_links: true, symlinks: true, xattrs: true, acls: true, rename: true, identity: true, delta: true, times: "nanosecond" },
    #[cfg(windows)]
    Scheme { name: "file", syntax: "C:\\path or file:///C:/path", summary: "a local NTFS directory; reparse points are refused, POSIX metadata is not translated", writable: true, sparse: true, hard_links: true, symlinks: false, xattrs: false, acls: false, rename: true, identity: true, delta: false, times: "100 nanoseconds" },
    Scheme { name: "nfs", syntax: "host:/export[:/sub] or nfs://host/export", summary: "an NFS export reached with the built-in v3 or v4.0 client", writable: true, sparse: true, hard_links: true, symlinks: true, xattrs: true, acls: true, rename: true, identity: true, delta: true, times: "nanosecond" },
    Scheme { name: "ssh", syntax: "ssh://[user@]host[:port]/path", summary: "a directory on a host that has rcp, through `rcp serve` over ssh", writable: true, sparse: true, hard_links: true, symlinks: true, xattrs: true, acls: true, rename: true, identity: true, delta: true, times: "nanosecond" },
    // `rcp` and `rcps` are the ssh adapter over a socket, so every capability matches the
    // `ssh` row above: same frames, same serve, same `Tree` on the far side.
    Scheme { name: "rcp", syntax: "rcp://host:port/path", summary: "the same `rcp serve`, over a socket it holds with -listen; plaintext, so the serve may bind only loopback", writable: true, sparse: true, hard_links: true, symlinks: true, xattrs: true, acls: true, rename: true, identity: true, delta: true, times: "nanosecond" },
    Scheme { name: "rcps", syntax: "rcps://host:port/path", summary: "the same socket inside TLS; with -tls.clientca the serve authenticates the peer, which is what lets it bind a routable address", writable: true, sparse: true, hard_links: true, symlinks: true, xattrs: true, acls: true, rename: true, identity: true, delta: true, times: "nanosecond" },
    Scheme { name: "sftp", syntax: "sftp://[user@]host[:port]/path", summary: "a directory on a host that has only OpenSSH, through its sftp subsystem", writable: true, sparse: false, hard_links: true, symlinks: true, xattrs: false, acls: false, rename: true, identity: false, delta: true, times: "second" },
    Scheme { name: "s3", syntax: "s3://bucket[/prefix]", summary: "an S3 bucket; POSIX metadata rides in user metadata", writable: true, sparse: false, hard_links: false, symlinks: true, xattrs: false, acls: false, rename: true, identity: false, delta: false, times: "nanosecond" },
    Scheme { name: "hdfs", syntax: "hdfs://namenode:port/path or hdfs:///path", summary: "an HDFS path over WebHDFS", writable: true, sparse: false, hard_links: false, symlinks: false, xattrs: false, acls: false, rename: true, identity: false, delta: false, times: "millisecond" },
    Scheme { name: "oci", syntax: "oci://host[:port]/repository[:tag]", summary: "a container registry's repository as an OCI image layout", writable: true, sparse: false, hard_links: false, symlinks: false, xattrs: false, acls: false, rename: false, identity: false, delta: false, times: "none" },
    Scheme { name: "tar", syntax: "tar://ARCHIVE[!/SUBPATH]", summary: "a tar archive as a tree: read any member, or write a new archive (ustar with pax headers, holes carried as GNU pax 1.0 sparse members); .tar.gz and .tar.zst are read by their magic and written by their name", writable: true, sparse: true, hard_links: true, symlinks: true, xattrs: false, acls: false, rename: false, identity: true, delta: false, times: "nanosecond" },
    Scheme { name: "smb", syntax: "smb://[user@]host[:port]/share[/path]", summary: "a Windows, Samba or NAS share over SMB2 (dialects 0x0202-0x0300, NTLMv2)", writable: true, sparse: false, hard_links: false, symlinks: false, xattrs: false, acls: false, rename: true, identity: false, delta: false, times: "100-nanosecond" },
    Scheme { name: "dav", syntax: "dav://host[:port]/path or davs://...", summary: "a WebDAV collection (Nextcloud, SharePoint, Apache mod_dav)", writable: true, sparse: false, hard_links: false, symlinks: false, xattrs: false, acls: false, rename: true, identity: false, delta: false, times: "none" },
    Scheme { name: "http", syntax: "https://host[:port]/path or http://...", summary: "a web server as a READ-ONLY tree, listed from rcp-index.json, an nginx JSON autoindex or an Apache HTML one", writable: false, sparse: false, hard_links: false, symlinks: false, xattrs: false, acls: false, rename: false, identity: false, delta: false, times: "second with rcp-index.json, none from an autoindex" },
];

/// The events `-json` emits and the fields each carries.
pub const EVENTS: &[(&str, &str)] = &[
    ("entry", "a file, directory or symlink completed: path, kind (f|d|l), size, mtime_ns, mode, and digest when the run hashed it"),
    ("removed", "sync removed an entry the source dropped: path"),
    ("deferred", "the destination will remove the entry itself, later (a registry's garbage collector): path and why; not a failure"),
    ("kept", "the destination refused to remove the entry and it is still there (a lock, a namenode's no): path and why; the run fails"),
    ("difference", "verify found one: kind, path, detail"),
    ("warning", "something worth saying that did not fail the run: message"),
    ("error", "an entry or the run failed: code, message, and op and path for an entry"),
    ("done", "the command ended: status (passed|failed), command, and that command's counts"),
];

/// Every code an `error` event can carry. Closed on purpose: a caller may branch on these
/// and a later release will not hand it a name it has never seen.
/// What kind of value an option takes, for a caller deciding whether it may set it.
pub fn capability_of(option: &str) -> Option<Capability> {
    OPTIONS
        .iter()
        .find(|(n, _, _)| *n == option)
        .map(|(_, c, _)| *c)
}

/// An argument list with the VALUE of every `Capability::Credential` option replaced, for
/// the places that write a command line down or hand it to another machine.
///
/// Derived from `OPTIONS` rather than from a list beside it, and that is the whole point.
/// Three sites had their own hand-kept lists and each was wrong in the same way: a
/// credential option added later was not in them, so it was written to disk or put on a
/// remote command line while the list said the site was covered. A deny-list of "things
/// that are not secret" fails open; this asks the table that already classifies them.
///
/// `valued` is the parser's own list of options that take a separate value, so this walks
/// the arguments with the same grammar the parser does and cannot mistake a value for the
/// next option. An option written `-k=v` is redacted too.
/// The command word in a recorded argv, or `None` if there is not one.
///
/// Two defects it replaces, both in `rcp job show`'s advice line. It read the first
/// argument not starting with `-`, so `rcp -parallel 8 sync A B` reported the verb as
/// `"8"`; and it matched only `Some("sync")`, so `isync` -- which plans removals exactly
/// as `sync` does -- was told to finish with `rcp resume`, a command that never plans a
/// removal and therefore cannot. Advice that cannot work is worse than none: it costs the
/// operator a run before they learn it was wrong.
///
/// The walk consumes each valued option's value so it cannot be mistaken for the verb, and
/// then requires the token to be a command `describe` actually knows, so a stray operand
/// is not promoted to a verb either.
pub fn verb_of<'a>(argv: &'a [String], valued: &[&str]) -> Option<&'a str> {
    let mut i = 0;
    while i < argv.len() {
        let arg = &argv[i];
        i += 1;
        if let Some(name) = arg.strip_prefix('-') {
            let name = name.split_once('=').map_or(name, |(n, _)| n);
            if valued.contains(&name) && !arg.contains('=') {
                i += 1;
            }
            continue;
        }
        if COMMANDS.iter().any(|c| c.name == arg.as_str()) {
            return Some(arg.as_str());
        }
    }
    None
}

/// Whether a verb plans removals, and so cannot be finished by `resume`.
///
/// `resume` re-plans a COPY against the catalog: it walks what was not recorded and copies
/// it, and it never plans a removal. So for any verb that sweeps the destination, the
/// remedy is the same verb again, not `resume`. Both sweeping verbs are named here --
/// `isync` is the CLI spelling of `Mode::Mirror` and was the one the old `Some("sync")`
/// match missed.
pub fn sweeps(verb: &str) -> bool {
    matches!(verb, "sync" | "isync")
}

pub fn redact_credentials(argv: &[String], valued: &[&str]) -> Vec<String> {
    const HIDDEN: &str = "<redacted>";
    let mut out = Vec::with_capacity(argv.len());
    let mut i = 0;
    while i < argv.len() {
        let arg = &argv[i];
        let name = arg.trim_start_matches('-');
        let (name, inline) = match name.split_once('=') {
            Some((n, _)) => (n, true),
            None => (name, false),
        };
        let secret = arg.starts_with('-') && capability_of(name) == Some(Capability::Credential);
        if secret && inline {
            out.push(format!("-{name}={HIDDEN}"));
            i += 1;
            continue;
        }
        out.push(arg.clone());
        i += 1;
        // a valued option's value is the next argument, whether or not it is secret: the
        // walk has to consume it either way or it reads the value as an option name
        if arg.starts_with('-') && valued.contains(&name) {
            if let Some(v) = argv.get(i) {
                out.push(if secret {
                    HIDDEN.to_string()
                } else {
                    v.clone()
                });
                i += 1;
            }
        }
    }
    out
}

pub const CODES: &[(&str, &str)] = &[
    (
        "notfound",
        "the path, export, bucket, repository or tag is not there",
    ),
    ("permission", "the credentials do not allow it"),
    ("exists", "something is already there"),
    (
        "unsupported",
        "the protocol or filesystem has no way to do it",
    ),
    (
        "invalid",
        "the request was refused as malformed, or the data did not check out",
    ),
    ("timeout", "the far side did not answer in time"),
    ("interrupted", "the operation was interrupted"),
    ("disconnected", "the connection ended mid-operation"),
    ("unreachable", "the host or network could not be reached"),
    ("nospace", "the destination is full"),
    (
        "quota",
        "a quota was exceeded, which more space elsewhere will not fix",
    ),
    (
        "busy",
        "the far side is throttling or overloaded; worth retrying, unlike most of this list",
    ),
    ("wouldblock", "the resource was busy"),
    (
        "io",
        "any other I/O error; the fallback, so the set above stays closed",
    ),
    (
        "owner",
        "ownership could not be preserved and -chown made that an error",
    ),
    ("usage", "the arguments, an option, or an endpoint's shape"),
];

pub const EXIT_CODES: &[(u8, &str)] = &[
    (0, "the command passed (STATUS: PASSED)"),
    (
        1,
        "the command failed (STATUS: FAILED); the events say what",
    ),
];

/// What an option's value IS, which decides whether a caller that is not a person at a
/// terminal may set it.
///
/// There is deliberately no default variant and no fallback: every option the parser
/// knows appears in the table below with one of these, and `tests/describe.rs` fails the
/// build when one does not. A denylist of the dangerous names was the previous answer and
/// it closed the holes that were known -- the tenth capability-bearing option added later
/// would have been exposed until somebody remembered a second table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    /// A number, a size, a pattern, a name, an enum: it changes how the work is done and
    /// reaches nothing the endpoints do not.
    Setting,
    /// Names a program to run, or a host to run one on.
    Runs,
    /// Names a path that is not one of the command's endpoints. `-allow` does check it --
    /// it is opened through `open_tree`, like any endpoint -- but it is a second source the
    /// operator reading the command line did not name, which is why a call may not set one
    /// even though a railed command line may.
    Path,
    /// Points the traffic at a service other than the endpoint's own.
    Service,
    /// Chooses or carries a credential.
    Credential,
    /// Weakens how a connection is made: plaintext instead of TLS, a certificate nobody
    /// checked, or an NFS auth flavor and protocol version the operator did not choose.
    ///
    /// Its own class because the existing two questions give different answers for it and
    /// no other variant does. It does not change WHICH host is reached -- `-allow` still
    /// holds, and `Away` still bounds every hand-off -- so it is not a `Service`. But it
    /// decides whether the wire to that host is worth anything, and as a `Setting` a call
    /// could set it: an MCP caller could answer a railed server with
    /// `options: ["-oci.noverify"]` and turn certificate verification off for a host the
    /// operator named. An operator writing the command line may choose plaintext; a caller
    /// composing a call into somebody else's rails may not.
    ///
    /// `-nfs.sec` and `-nfs.vers` belong here too, and they show why the class exists:
    /// enumerating the OPTIONS table for any other `Setting` that changes security posture
    /// is how they turn up. As a `Setting`, a server started `-nfs.sec krb5p` relays
    /// nothing -- a `Setting` reaches no child -- so every call runs AUTH_SYS, and a caller
    /// can name the flavor itself besides. Both halves are closed: the class refuses it
    /// from a call, and `relay_env` carries the operator's choice to the child.
    Transport,
    /// A rail, or the catalog and event stream the server owns: never set by a call.
    Rail,
}

impl Capability {
    /// Why a call may not set an option of this kind; `None` for one it may.
    pub fn why_not(self) -> Option<&'static str> {
        match self {
            Capability::Setting => None,
            Capability::Runs => Some("names a program to run, or a host to run one on"),
            Capability::Path => Some("names a path outside the call's endpoints"),
            Capability::Service => Some("sends the traffic to another service"),
            Capability::Credential => Some("chooses or carries a credential"),
            Capability::Transport => Some("weakens how the connection is made"),
            Capability::Rail => Some("is set by the server, not by the call"),
        }
    }

    /// Why a railed command line may not set an option of this kind; `None` for one it may.
    ///
    /// Not the same question as `why_not`, and the difference was a measured hole. A call
    /// through the MCP server is refused everything but a `Setting`, because the server
    /// operator wrote the rails and the caller wrote the call. A command line is written by
    /// whoever set `-allow`, so `Rail` is theirs by definition and `Path` is theirs because
    /// `open_tree` puts it through the same `-allow` check as any endpoint.
    ///
    /// What is left is what no rail can see. `-allow` bounds the TEXT of an endpoint, and
    /// `-s3.endpoint`, `-hdfs.namenode`, `-s3.profile` and `-oci.user` change which service
    /// that text is resolved against and with whose credentials. Measured: `scan -allow
    /// s3://corp/bucket -s3.endpoint http://127.0.0.1:8931 s3://corp/bucket` sent
    /// `GET /corp/?list-type=2&prefix=bucket/` to a stand-in on loopback, a host the rail
    /// never named, and the same run without `-s3.endpoint` goes to AWS.
    ///
    /// Say plainly what this does and does not do, because it is easy to overstate. It
    /// MOVES the capability to the environment; it does not remove it. `RCP_S3_ENDPOINT`
    /// redirects the same traffic, and so do AWS's own `AWS_ENDPOINT_URL_S3`,
    /// `AWS_ENDPOINT_URL` and an `endpoint_url` in the named profile -- which rcp reads
    /// because AWS's own tools do. The rails are not a boundary against the environment a
    /// run inherits and do not claim to be; what they bound is the COMMAND LINE, which is
    /// the part a caller writes and an operator reads. Where those are the same party, this changes nothing. Where they
    /// are not -- an MCP server holding the rails, a caller composing the call -- the
    /// caller writes the command line and the server owns the environment, which is
    /// exactly the split this rests on.
    pub fn why_not_railed(self) -> Option<&'static str> {
        match self {
            // `Transport` is here rather than below because the rail it could evade does
            // not exist: `-allow` bounds where a run goes, not how well the connection to
            // there is authenticated. An operator who wrote `-allow oci://reg.local/app`
            // and `-oci.insecure` in the same line said both things on purpose.
            Capability::Setting | Capability::Path | Capability::Rail | Capability::Transport => {
                None
            }
            Capability::Runs | Capability::Service | Capability::Credential => self.why_not(),
        }
    }
}

/// A capability and a summary per option, looked up by the option's own name. The names
/// come from the parser's tables, so this list is checked for completeness rather than
/// trusted -- and the capability with them, which is what makes a new option classified
/// by construction instead of by memory.
pub const OPTIONS: &[(&str, Capability, &str)] = &[
    // where the work happens and how much of it
    ("parallel", Capability::Setting, "worker count, or auto[:N] for the online tuner of workers plus read and write concurrency (default: CPUs, 2 to 8)"),
    ("listen", Capability::Setting, "serve: an address to serve the protocol on (loopback, unless -tls.cert, -tls.key and -tls.clientca are all set; -allow is required)"),
    ("bs", Capability::Setting, "read and write block size (default 1m)"),
    ("engine", Capability::Setting, "auto, uring or threads"),
    ("depth", Capability::Setting, "stop below this depth"),
    ("bwlimit", Capability::Setting, "read at most this many bytes a second (at least 4k)"),
    ("nodes", Capability::Runs, "comma-separated hosts to spread the copy or scan over"),
    ("copybatch", Capability::Runs, "a program to run per batch instead of copying here"),
    ("dircount", Capability::Setting, "NFS readdir buffer size (1k to 4m)"),
    // the catalog
    ("catalog", Capability::Rail, "the catalog directory (else RCP_CATALOG, else the state directory)"),
    ("newid", Capability::Setting, "record this run under a new catalog id"),
    ("id", Capability::Setting, "the catalog id to resume, sync, scan from or delete"),
    ("noid", Capability::Setting, "keep no catalog for this run"),
    ("snap", Capability::Path, "resume or sync from this source instead of the catalog's"),
    // what is selected
    ("match", Capability::Setting, "keep paths matching this glob (repeatable)"),
    ("exclude", Capability::Setting, "drop paths matching this glob (repeatable)"),
    ("minsize", Capability::Setting, "files at least this large"),
    ("maxsize", Capability::Setting, "files at most this large"),
    ("newer", Capability::Setting, "files modified within this age"),
    ("older", Capability::Setting, "files untouched for this age"),
    ("type", Capability::Setting, "f, d or l"),
    ("uid", Capability::Setting, "files owned by this user"),
    ("gid", Capability::Setting, "files owned by this group"),
    ("fileid", Capability::Setting, "the entry with this inode number"),
    // what travels
    ("nohash", Capability::Setting, "no digest in the catalog; the kernel may copy the bytes"),
    ("sha256", Capability::Setting, "digest with SHA-256 (the default)"),
    ("blake3", Capability::Setting, "digest with BLAKE3"),
    ("xxh3", Capability::Setting, "digest with XXH3-64, the hash rsync and rclone speak; fast and NOT cryptographic"),
    ("xxh128", Capability::Setting, "digest with XXH3-128, the hash rsync and rclone speak; fast and NOT cryptographic"),
    ("md5", Capability::Setting, "accepted for compatibility; the run's digest is unchanged"),
    ("delta", Capability::Setting, "send a file the destination already has as a patch against it"),
    ("compress", Capability::Setting, "compress the payloads on an ssh:// or rcp:// stream"),
    // A `Setting`, like `-compress` itself: it trades CPU for bandwidth on a stream the
    // caller already chose, and cannot send the run anywhere else or weaken what
    // authenticates it. The far side answers which codec it will use, so naming one it
    // does not know costs ratio, never correctness.
    ("compress.codec", Capability::Setting, "lz4 (fast, the default), deflate or zstd (slower, smaller on text); implies -compress"),
    // Same class, and for a sharper reason: the level never has to be agreed. A DEFLATE
    // stream carries its own code tables, so the decoder does not need to know what the
    // encoder was told -- the number is a request for effort, not a property of the wire.
    // It is refused on a codec that has no level, which is the same rule as refusing an
    // out-of-range one: the caller is at a terminal and can still answer.
    ("compress-codec", Capability::Setting, "the same as -compress.codec, the spelling the first zstd change used"),
    ("compress.level", Capability::Setting, "how hard deflate works, 1..9 (default 6); needs -compress.codec deflate, since neither lz4 nor this crate's zstd encoder has a level; implies -compress"),
    ("nolinks", Capability::Setting, "copy hard links as separate files"),
    ("noxattr", Capability::Setting, "skip extended attributes and ACLs"),
    ("acl4", Capability::Setting, "carry NFSv4 ACLs on NFS endpoints"),
    ("chown", Capability::Setting, "ownership must be preserved: fail otherwise"),
    ("noown", Capability::Setting, "never touch ownership"),
    ("preserve-atime", Capability::Setting, "leave the source's access times as they were"),
    ("fsync", Capability::Setting, "flush every file to stable storage"),
    ("nocache", Capability::Setting, "drop what was written from the page cache"),
    ("dryrun", Capability::Setting, "plan and report, write nothing"),
    ("force", Capability::Setting, "actually remove (delete counts without it)"),
    ("removetopdir", Capability::Setting, "remove the top directory too"),
    ("replace", Capability::Setting, "overwrite what is already there"),
    // verify
    ("nodata", Capability::Setting, "compare metadata only"),
    ("noattrs", Capability::Setting, "compare content only"),
    ("nomods", Capability::Setting, "ignore modification times"),
    ("mtimewindow", Capability::Setting, "tolerate this many seconds of modification-time difference"),
    // reporting
    ("json", Capability::Rail, "the run's events on stdout as JSON, one object per line; human lines move to stderr"),
    ("allow", Capability::Rail, "a root this run may touch, repeatable; outside it every endpoint is refused before it is opened"),
    ("readonly", Capability::Rail, "refuse every command that writes to an endpoint; rcp still records the run in the catalog's jobs.log"),
    ("confirm", Capability::Rail, "the plan digest a dry run printed; the run proceeds only if the plan still has that digest"),
    ("requireconfirm", Capability::Rail, "refuse a run that would remove or overwrite unless -confirm matches"),
    ("v", Capability::Setting, "one line per entry"),
    ("l", Capability::Setting, "the long listing"),
    ("q", Capability::Setting, "no per-entry output"),
    ("stats", Capability::Setting, "the statistics report"),
    ("csv", Capability::Setting, "report as comma-separated values"),
    ("html", Capability::Setting, "report as HTML"),
    ("fmt", Capability::Setting, "a format string per entry"),
    ("du", Capability::Setting, "report sizes as du does"),
    ("duk", Capability::Setting, "report sizes as du -k does"),
    ("edupe", Capability::Setting, "report duplicate files"),
    ("hashcache", Capability::Setting, "reuse a remembered digest when size, mtime and inode all still agree"),
    ("rsyncable", Capability::Setting, "cut .tar.gz members at content-defined boundaries, so an edit does not change every later member"),
    ("nonames", Capability::Setting, "numeric user and group ids"),
    ("progress", Capability::Setting, "a progress line on stderr every few seconds"),
    ("noprogress", Capability::Setting, "no progress lines"),
    ("loglevel", Capability::Setting, "INFO or DEBUG"),
    ("all", Capability::Setting, "show everything, not just the usual subset"),
    ("h", Capability::Setting, "the usage text"),
    ("help", Capability::Setting, "the usage text"),
    ("version", Capability::Setting, "the version and transports"),
    ("V", Capability::Setting, "the version and transports"),
    // estimate
    ("sample", Capability::Setting, "how many bytes to read for the rate sample"),
    ("gbit", Capability::Setting, "the link speed to project against"),
    ("t", Capability::Setting, "how long a live test copy may run, or how long `job wait` waits"),
    // chown and chmod
    ("user", Capability::Setting, "the user to set"),
    ("group", Capability::Setting, "the group to set"),
    ("user-from", Capability::Setting, "only change entries owned by this user"),
    ("group-from", Capability::Setting, "only change entries owned by this group"),
    ("reference", Capability::Path, "take the mode or owner from this path"),
    ("mode", Capability::Setting, "the mode to set"),
    // transports
    ("rcp.remote", Capability::Runs, "the rcp to run on an ssh:// host"),
    ("via", Capability::Runs, "an ssh://[user@]host[:port] or rcp://host:port whose rcp serve opens every remote endpoint of this run on its behalf"),
    // Transport, not Credential, and the reason was measured rather than argued. These
    // configure HOW WELL the connection to a named endpoint is authenticated -- the same
    // question as `-oci.insecure` and `-nfs.sec`, which is what `Transport` is for -- and a
    // `Credential` is refused on any RAILED command line. `serve -listen` is railed by
    // construction (it will not start without `-allow`), so as `Credential` all four were
    // options that could never be used: the first run of the contract arm came back
    // "-tls.cert chooses or carries a credential, which no rail can bound". A CLI option
    // that is unreachable on the only command that needs it is worse than no option.
    // What is preserved either way is the half that matters: `Transport` is still refused
    // from an MCP CALL, so a caller cannot name the trust anchor a railed server checks
    // against, and `relay_env` still carries the operator's choice into every child.
    // What is given up is the value REDACTION `Credential` brings -- and these values are
    // file paths, not keys, so a debug line reading `-tls.key /etc/rcp/serve.key` says
    // where to look and discloses nothing that `ls` would not.
    ("tls.ca", Capability::Transport, "the PEM bundle an rcps:// client checks the serve's certificate against (default: the system bundle)"),
    ("tls.cert", Capability::Transport, "this side's certificate chain (PEM): what a serve -listen presents, and what an rcps:// client presents when asked"),
    ("tls.key", Capability::Transport, "the private key for -tls.cert (PKCS#8, PKCS#1 or SEC1)"),
    ("tls.clientca", Capability::Transport, "the PEM bundle a serve -listen requires the peer's certificate to come from; naming it is what turns mutual TLS on, and what lets a serve bind anything but loopback"),
    ("nfs.sec", Capability::Transport, "sys, krb5, krb5i or krb5p"),
    ("nfs.vers", Capability::Transport, "3 or 4"),
    ("hdfs.namenode", Capability::Service, "the namenode for hdfs:///path"),
    ("s3.endpoint", Capability::Service, "the S3 service to talk to"),
    ("s3.profile", Capability::Credential, "the AWS profile to take credentials from"),
    ("s3.insecure", Capability::Transport, "use http when the S3 endpoint names no scheme"),
    ("s3.noverify", Capability::Transport, "skip certificate verification"),
    ("oci.user", Capability::Credential, "USER:PASSWORD for the registry"),
    ("dav.user", Capability::Credential, "USER:PASSWORD for the WebDAV server"),
    ("smb.user", Capability::Credential, "[DOMAIN\\]USER:PASSWORD for the SMB share"),
    // A `Setting`, not `Transport`, and deliberately: that class is for options that can
    // WEAKEN how a connection is made, which is why a call may not set them. This one can
    // only make the connection stricter, so a caller asking for it is asking for less trust
    // in the network, never more.
    ("smb.sign", Capability::Setting, "sign and verify every SMB message even when the server does not ask, so an edit that clears its signing bit is refused"),
    ("smb.handshake", Capability::Transport, "seconds an SMB handshake may take before the connection is retried (default 10)"),
    ("dav.insecure", Capability::Transport, "use http for davs:// endpoints"),
    ("dav.noverify", Capability::Transport, "skip certificate verification for davs:// endpoints"),
    ("http.user", Capability::Credential, "USER:PASSWORD for an http:// or https:// source"),
    ("http.noverify", Capability::Transport, "skip certificate verification for https:// sources"),
    ("http.index", Capability::Path, "the published index to look for (default rcp-index.json; empty forces the autoindex readers)"),
    ("oci.insecure", Capability::Transport, "use http for oci:// endpoints"),
    ("oci.noverify", Capability::Transport, "skip certificate verification for oci:// endpoints"),
    // diag
    ("rmrf", Capability::Setting, "diag: remove this tree"),
    ("cat", Capability::Setting, "diag: print this file"),
    ("mkdir", Capability::Setting, "diag: make this directory"),
    ("rmdir", Capability::Setting, "diag: remove this empty directory"),
    ("rmid", Capability::Setting, "diag: remove this catalog"),
    ("n", Capability::Setting, "the offset to read a job log from, and diag: how many"),
    ("rand%", Capability::Setting, "diag: percentage of random access"),
    ("read%", Capability::Setting, "diag: percentage of reads"),
    ("npend", Capability::Setting, "diag: how many operations in flight"),
    ("size", Capability::Setting, "diag: how large"),
    ("u", Capability::Setting, "diag: user"),
    ("g", Capability::Setting, "diag: group"),
    // Path, not Setting: each NAMES A FILE that `diag change` reads through
    // `fs::read_to_string`, and as a Setting no rail would stand in the way at all.
    ("umap", Capability::Path, "diag: user id mapping, read from this file"),
    ("gmap", Capability::Path, "diag: group id mapping, read from this file"),
    ("atime", Capability::Setting, "diag: the access time to set"),
    ("mtime", Capability::Setting, "diag: the modification time to set"),
    ("top-match", Capability::Setting, "diag: match at the top level"),
    ("branch-match", Capability::Setting, "diag: match a branch"),
    ("m", Capability::Setting, "diag: a measure argument"),
    ("j", Capability::Setting, "diag: a job argument"),
    ("read", Capability::Setting, "diag: read"),
    ("write", Capability::Setting, "diag: write"),
    ("random", Capability::Setting, "diag: random access"),
    ("sequential", Capability::Setting, "diag: sequential access"),
    ("wrdata", Capability::Setting, "diag: write data"),
    ("rebuild", Capability::Setting, "diag: rebuild the index"),
];

pub fn summary_of(option: &str) -> Option<&'static str> {
    OPTIONS
        .iter()
        .find(|(n, _, _)| *n == option)
        .map(|(_, _, s)| *s)
}

fn field(key: &str, value: &str) -> String {
    format!("{}:{}", quote(key), quote(value))
}

fn flag(key: &str, value: bool) -> String {
    format!("{}:{value}", quote(key))
}

/// The whole description: one JSON object, pretty-printed one entry per line so a person
/// can read it too.
pub fn describe(version: &str, transports: &str, valued: &[&str], switches: &[&str]) -> String {
    let mut out = String::with_capacity(16 << 10);
    out.push_str(&format!(
        "{{\n  \"rcp\": {},\n  \"transports\": {},\n",
        quote(version),
        quote(transports)
    ));

    out.push_str("  \"commands\": [\n");
    let commands: Vec<_> = COMMANDS
        .iter()
        .filter(|c| {
            !cfg!(windows)
                || !matches!(
                    c.name,
                    "chmod"
                        | "chown"
                        | "diag"
                        | "job"
                        | "mcp"
                        | "copybatch"
                        | "scanbatch"
                        | "show"
                        | "serve"
                )
        })
        .collect();
    for (i, c) in commands.iter().enumerate() {
        out.push_str(&format!(
            "    {{{}, {}, {}, {}}}{}\n",
            field("name", c.name),
            field("takes", c.takes),
            field("summary", c.summary),
            flag("writes", c.writes),
            if i + 1 < commands.len() { "," } else { "" }
        ));
    }
    out.push_str("  ],\n");

    out.push_str("  \"options\": [\n");
    let all: Vec<(&str, &str)> = valued
        .iter()
        .map(|n| (*n, "value"))
        .chain(switches.iter().map(|n| (*n, "switch")))
        .collect();
    for (i, (name, kind)) in all.iter().enumerate() {
        let summary = summary_of(name).unwrap_or("");
        // `settable` is what a caller that is not a person at a terminal may set: an
        // option whose value is a program, a path, a service or a credential is not one,
        // and `rcp mcp` refuses it. Published so an agent reads the rule rather than
        // learning it from a refusal.
        let settable = capability_of(name).is_some_and(|c| c.why_not().is_none());
        out.push_str(&format!(
            "    {{{}, {}, {}, {}}}{}\n",
            field("name", name),
            field("kind", kind),
            flag("settable_by_a_call", settable),
            field("summary", summary),
            if i + 1 < all.len() { "," } else { "" }
        ));
    }
    out.push_str("  ],\n");

    out.push_str("  \"endpoints\": [\n");
    for (i, s) in SCHEMES.iter().enumerate() {
        out.push_str(&format!(
            "    {{{}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}}}{}\n",
            field("scheme", s.name),
            field("syntax", s.syntax),
            field("summary", s.summary),
            flag("writable", s.writable),
            flag("sparse", s.sparse),
            flag("hard_links", s.hard_links),
            flag("symlinks", s.symlinks),
            flag("xattrs", s.xattrs),
            flag("acls", s.acls),
            flag("rename", s.rename),
            flag("identity", s.identity),
            flag("delta", s.delta),
            field("times", s.times),
            if i + 1 < SCHEMES.len() { "," } else { "" }
        ));
    }
    out.push_str("  ],\n");

    out.push_str("  \"events\": [\n");
    for (i, (name, what)) in EVENTS.iter().enumerate() {
        out.push_str(&format!(
            "    {{{}, {}}}{}\n",
            field("event", name),
            field("summary", what),
            if i + 1 < EVENTS.len() { "," } else { "" }
        ));
    }
    out.push_str("  ],\n");

    out.push_str("  \"codes\": [\n");
    for (i, (name, what)) in CODES.iter().enumerate() {
        out.push_str(&format!(
            "    {{{}, {}}}{}\n",
            field("code", name),
            field("summary", what),
            if i + 1 < CODES.len() { "," } else { "" }
        ));
    }
    out.push_str("  ],\n");

    out.push_str("  \"exit\": [\n");
    for (i, (code, what)) in EXIT_CODES.iter().enumerate() {
        out.push_str(&format!(
            "    {{{}:{code}, {}}}{}\n",
            quote("code"),
            field("summary", what),
            if i + 1 < EXIT_CODES.len() { "," } else { "" }
        ));
    }
    out.push_str("  ]\n}\n");
    out
}
