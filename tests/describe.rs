//! `rcp describe` is only worth reading if it cannot fall behind the binary. These arms
//! are the mechanism: the description is built from the parser's own option tables, so an
//! option that exists without a summary fails here, and a scheme or command described but
//! not accepted fails here too. Each arm has a control that fails when the property is
//! removed, because an arm that only shows the present state would pass whether or not the
//! guarantee held.

use std::collections::BTreeSet;
use std::process::Command;

use rcp::describe::{capability_of, summary_of, Capability, COMMANDS, OPTIONS, SCHEMES};

/// The option tables the argument parser matches against, read out of its source. Reading
/// them rather than copying them is the point: a copy would be the drift this prevents.
fn parser_options() -> (Vec<String>, Vec<String>) {
    let src = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/main.rs"),
    )
    .expect("main.rs");
    let names = |after: &str| -> Vec<String> {
        let start = src.find(after).unwrap_or_else(|| {
            panic!("{after} is no longer in main.rs; this test reads the parser's own tables")
        }) + after.len();
        let end = src[start..].find("];").expect("the table ends") + start;
        src[start..end]
            .split('"')
            .skip(1)
            .step_by(2)
            .map(str::to_string)
            .collect()
    };
    (
        names("const VALUED: &[&str] = &["),
        names("const SWITCHES: &[&str] = &["),
    )
}

fn rcp(args: &[&str]) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_rcp"))
        .args(args)
        .output()
        .expect("rcp runs");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn every_option_the_parser_accepts_is_described() {
    let (valued, switches) = parser_options();
    assert!(
        valued.len() > 40 && switches.len() > 30,
        "the tables were read as {} and {} entries, which is not plausible",
        valued.len(),
        switches.len()
    );
    let missing: Vec<&String> = valued
        .iter()
        .chain(&switches)
        .filter(|n| summary_of(n).is_none())
        .collect();
    assert!(
        missing.is_empty(),
        "options the parser accepts with no summary in describe.rs:\n{missing:?}"
    );
    // and the reverse: a summary for an option that no longer exists is a stale line
    let known: BTreeSet<&str> = valued.iter().chain(&switches).map(String::as_str).collect();
    let stale: Vec<&str> = OPTIONS
        .iter()
        .map(|(n, _, _)| *n)
        .filter(|n| !known.contains(n))
        .collect();
    assert!(
        stale.is_empty(),
        "summaries for options the parser no longer accepts:\n{stale:?}"
    );
    // the control: an option the parser does not have is reported, so the arm above is
    // not passing because the check never fires
    assert!(summary_of("an-option-that-does-not-exist").is_none());
}

/// Every option carries a capability, and the two that read it -- the MCP server and the
/// rails -- read that rather than a list of their own. This is the arm that makes a new
/// option classified by construction: add one to the parser and this fails until it is.
#[test]
fn every_option_is_classified_and_the_dangerous_ones_are_not_settings() {
    let (valued, switches) = parser_options();
    let unclassified: Vec<&String> = valued
        .iter()
        .chain(&switches)
        .filter(|n| capability_of(n).is_none())
        .collect();
    assert!(
        unclassified.is_empty(),
        "options the parser accepts with no capability in describe.rs:\n{unclassified:?}"
    );

    // the ones a measurement already proved dangerous, by name, so a reclassification to
    // Setting fails here rather than on someone's machine
    for (name, want) in [
        ("copybatch", Capability::Runs),
        ("nodes", Capability::Runs),
        ("rcp.remote", Capability::Runs),
        ("snap", Capability::Path),
        ("reference", Capability::Path),
        ("s3.endpoint", Capability::Service),
        ("hdfs.namenode", Capability::Service),
        ("s3.profile", Capability::Credential),
        ("oci.user", Capability::Credential),
        ("nfs.sec", Capability::Transport),
        ("nfs.vers", Capability::Transport),
        ("oci.insecure", Capability::Transport),
        ("oci.noverify", Capability::Transport),
        ("s3.insecure", Capability::Transport),
        ("s3.noverify", Capability::Transport),
        ("allow", Capability::Rail),
        ("confirm", Capability::Rail),
        ("catalog", Capability::Rail),
        ("readonly", Capability::Rail),
        ("json", Capability::Rail),
    ] {
        assert_eq!(capability_of(name), Some(want), "-{name}");
        assert!(
            capability_of(name).unwrap().why_not().is_some(),
            "-{name} must not be settable from a call"
        );
    }
    // the control: an ordinary setting is settable, or the check above would pass by
    // refusing everything
    assert_eq!(capability_of("parallel"), Some(Capability::Setting));
    assert!(capability_of("parallel").unwrap().why_not().is_none());
    assert!(capability_of("an-option-that-does-not-exist").is_none());
}

/// The command names the dispatch actually matches on, read from its source. Running each
/// one instead would be worse than useless here: `-h` short-circuits to the usage text for
/// every name, real or not, so a run would pass for a command that does not exist, and
/// `serve` and `copybatch` read stdin and would hang.
fn dispatched_commands() -> BTreeSet<String> {
    let src = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/main.rs"),
    )
    .expect("main.rs");
    // Anchored on a MARKER rather than on the match expression. It anchored on
    // `match args.command.as_str() {` and a second such match was added above it, so this
    // read five names and the assertion below -- "which is not plausible" -- is what
    // caught it. A test that locates code by a pattern the code may repeat is a test that
    // will one day measure the wrong code silently; this one was written not to.
    let start = src
        .find("// THE DISPATCH")
        .expect("the dispatch marker in main.rs");
    let start = src[start..]
        .find("match args.command.as_str() {")
        .expect("the dispatch")
        + start;
    let end = src[start..].find("\n    }\n}").expect("the dispatch ends") + start;
    let mut out = BTreeSet::new();
    for line in src[start..end].lines() {
        let t = line.trim_start();
        if !t.starts_with('"') {
            continue;
        }
        // `"copy" => ...` and `"a" | "b" => ...`, up to the arrow
        let head = t.split("=>").next().unwrap_or("");
        out.extend(head.split('"').skip(1).step_by(2).map(str::to_string));
    }
    out
}

#[test]
fn the_description_names_only_real_commands_and_schemes() {
    let dispatched = dispatched_commands();
    assert!(
        dispatched.len() > 15,
        "the dispatch was read as {} names, which is not plausible: {dispatched:?}",
        dispatched.len()
    );
    let unknown: Vec<&str> = COMMANDS
        .iter()
        .map(|c| c.name)
        .filter(|n| !dispatched.contains(*n))
        .collect();
    assert!(
        unknown.is_empty(),
        "described commands rcp does not dispatch:\n{unknown:?}"
    );
    // the control: a name that is not in the dispatch is seen as missing, so the check
    // above can fail, and rcp refuses it at run time
    assert!(!dispatched.contains("frobnicate"));
    let out = Command::new(env!("CARGO_BIN_EXE_rcp"))
        .arg("frobnicate")
        .output()
        .expect("rcp runs");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("unknown command"),
        "an unknown command must be refused"
    );

    // every described scheme parses as an endpoint, and the capability table is not all
    // one value (which would make it decoration rather than information)
    for s in SCHEMES {
        assert!(
            !s.syntax.is_empty() && !s.summary.is_empty(),
            "{} is described with nothing",
            s.name
        );
    }
    assert!(
        SCHEMES.iter().any(|s| s.sparse) && SCHEMES.iter().any(|s| !s.sparse),
        "the sparse column says the same thing for every scheme"
    );
    assert!(
        SCHEMES.iter().any(|s| s.hard_links) && SCHEMES.iter().any(|s| !s.hard_links),
        "the hard-link column says the same thing for every scheme"
    );
    assert!(
        SCHEMES.iter().any(|s| s.identity) && SCHEMES.iter().any(|s| !s.identity),
        "the identity column says the same thing for every scheme"
    );
    let local = SCHEMES
        .iter()
        .find(|s| s.name == "file")
        .expect("the local scheme");
    let oci = SCHEMES
        .iter()
        .find(|s| s.name == "oci")
        .expect("the oci scheme");
    assert!(
        local.hard_links && local.sparse && local.identity,
        "a local directory carries all three"
    );
    assert!(
        !oci.hard_links && !oci.symlinks && oci.times == "none",
        "a registry carries none of them"
    );
}

#[test]
fn describe_is_one_json_object_that_agrees_with_version() {
    let text = rcp(&["describe"]);
    // a reader that accepts only what this file is allowed to emit: a check that the
    // writer never has to escape its way out of a field
    assert!(
        text.starts_with('{') && text.trim_end().ends_with('}'),
        "not one object:\n{text}"
    );
    assert_eq!(text.matches("\"rcp\":").count(), 1);
    for section in [
        "\"commands\":",
        "\"options\":",
        "\"endpoints\":",
        "\"events\":",
        "\"codes\":",
        "\"exit\":",
    ] {
        assert!(text.contains(section), "no {section} in the description");
    }
    // the transports line is the one version prints, so the two cannot disagree
    let version = rcp(&["version"]);
    let line = version
        .lines()
        .find(|l| l.starts_with("transports: "))
        .expect("version names the transports")
        .trim_start_matches("transports: ");
    assert!(
        text.contains(line),
        "describe and version disagree about the transports:\n{line}"
    );
    // and it names this build: with the rustls feature the schemes speak https, without it
    // the line says so instead
    assert_eq!(line.contains("http and https"), cfg!(feature = "rustls"));
    assert_eq!(
        line.contains("needs a build with --features rustls"),
        !cfg!(feature = "rustls")
    );
}

/// The verb in a recorded argv, and whether it sweeps: the two facts `rcp job show` and the
/// copy summary use to decide whether `resume` is the remedy.
///
/// Both had defects. The verb was "the first argument not starting with `-`", which reads
/// an option's VALUE as the verb; and the sweep test was `== "sync"`, which misses `isync`,
/// the CLI spelling of the same planning mode. Either one sends an operator to `rcp resume`
/// for a run `resume` cannot finish -- and they only find that out after running it.
#[test]
fn the_verb_of_an_argv_survives_option_values_and_both_sweeping_verbs_are_known() {
    use rcp::describe::{sweeps, verb_of};
    const VALUED: &[&str] = &["parallel", "id", "newid", "exclude"];
    let argv = |s: &str| s.split(' ').map(String::from).collect::<Vec<_>>();

    // the defect: `8` is the value of -parallel, not the verb
    assert_eq!(
        verb_of(&argv("-parallel 8 sync -id x"), VALUED),
        Some("sync")
    );
    assert_eq!(verb_of(&argv("-l copy /a /b"), VALUED), Some("copy"));
    assert_eq!(
        verb_of(&argv("-parallel=8 isync /a /b"), VALUED),
        Some("isync")
    );
    // an operand is not a verb: nothing in the table matches, so nothing is claimed
    assert_eq!(verb_of(&argv("/some/path /other/path"), VALUED), None);
    assert_eq!(verb_of(&[], VALUED), None);

    // The case that needs the value-skipping walk, and the one the COMMANDS check alone
    // does NOT cover: an option value that IS a command name. `-newid sync` names a catalog
    // "sync"; the verb is `copy`.
    assert_eq!(
        verb_of(&argv("-newid sync copy /a /b"), VALUED),
        Some("copy")
    );
    // its control: declaring nothing valued is the old wiring, and it answers `sync`
    assert_eq!(
        verb_of(&argv("-newid sync copy /a /b"), &[]),
        Some("sync"),
        "the value-skipping walk is not doing anything"
    );

    assert!(
        sweeps("sync") && sweeps("isync"),
        "both sweeping verbs must be known"
    );
    assert!(
        !sweeps("copy") && !sweeps("resume") && !sweeps("verify"),
        "a copy is finished by resume"
    );
    // and every verb `sweeps` names must be a verb that exists
    for v in ["sync", "isync"] {
        assert!(
            COMMANDS.iter().any(|c| c.name == v),
            "sweeps names {v}, which is not a command"
        );
    }
}

/// The `xattrs` column of `SCHEMES` must match what the adapter's `keeps_xattrs` says.
///
/// Without this, nothing checks a single column of `describe`'s endpoint table against a
/// single adapter -- the file's own opening paragraph promises "the description is built
/// from the parser's own option tables, so an option that exists without a summary fails
/// here", and that covers options and command names only. A capability column could say
/// anything and no arm would notice, which is how a table whose whole job is to tell an
/// agent what an endpoint can carry drifts from what it carries.
///
/// A source scan rather than a live tree, because constructing an `s3`, `oci` or `dav`
/// tree needs a server. What it checks is the one thing the column is about: whether the
/// adapter declares `keeps_xattrs` false.
#[test]
fn every_scheme_the_parser_accepts_has_a_row() {
    use std::fs;
    use std::path::Path;
    // The scheme prefixes `Endpoint::parse` tests, read from the parser itself. A hand-kept
    // list here would have the same defect as the table it is checking.
    let src = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs"))
        .expect("src/lib.rs");
    let mut parsed: Vec<String> = Vec::new();
    let mut rest = src.as_str();
    while let Some(i) = rest.find("strip_prefix(\"") {
        let after = &rest[i + "strip_prefix(\"".len()..];
        let Some(j) = after.find('"') else { break };
        let literal = &after[..j];
        rest = &after[j..];
        if let Some(name) = literal.strip_suffix("://") {
            if !name.is_empty() && !parsed.iter().any(|p| p == name) {
                parsed.push(name.to_string());
            }
        }
    }
    // the scan found something, or every assertion below is vacuous
    assert!(
        parsed.len() >= 8,
        "only {} schemes found in the parser: {parsed:?}",
        parsed.len()
    );
    // `file://` is the local tree and is listed as `file`; everything else is named as spelled
    let missing: Vec<&String> = parsed
        .iter()
        .filter(|n| !SCHEMES.iter().any(|s| s.name == *n))
        .collect();
    assert!(missing.is_empty(), "the parser accepts these schemes and `describe` lists none of them, so an agent reading describe cannot know they exist: {missing:?}");

    // The same list has to reach the user, not only `describe`. The "endpoint is none of"
    // refusal is what someone sees after a typo, and it was four schemes out of date --
    // found by reading it in a real failure, not by reading the code.
    let refusal = src
        .split("is none of")
        .nth(1)
        .expect("the endpoint refusal names the schemes");
    let refusal = &refusal[..refusal.find("\")").unwrap_or(refusal.len())];
    let unlisted: Vec<&String> = parsed
        .iter()
        .filter(|n| *n != "file" && !refusal.contains(&format!("{n}://")))
        .collect();
    assert!(unlisted.is_empty(), "the parser accepts these and the endpoint refusal does not offer them: {unlisted:?}\n{refusal}");

    // The control: the check can fail. A scheme the parser does not accept is not in the
    // table by accident -- if this found a row for it, the comparison above proves nothing.
    assert!(!SCHEMES.iter().any(|s| s.name == "gopher"));
    assert!(!parsed.iter().any(|n| n == "gopher"));
    assert!(!refusal.contains("gopher://"));
}

#[test]
fn the_endpoint_table_agrees_with_what_each_adapter_declares() {
    use std::fs;
    use std::path::Path;
    // the file that implements each scheme's `Tree`
    let sources = [
        ("s3", "src/s3/client.rs"),
        ("hdfs", "src/hdfs/client.rs"),
        ("dav", "src/dav/client.rs"),
        ("http", "src/https/client.rs"),
        ("oci", "src/oci/client.rs"),
        ("sftp", "src/sftp/client.rs"),
    ];
    let mut checked = 0;
    for (scheme, rel) in sources {
        let row = SCHEMES
            .iter()
            .find(|s| s.name == scheme)
            .unwrap_or_else(|| panic!("no {scheme} row"));
        let text = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(rel))
            .unwrap_or_else(|e| panic!("{rel}: {e}"));
        // `fn keeps_xattrs(&self) -> bool { false }`, however it is laid out
        let at = text.find("fn keeps_xattrs").unwrap_or_else(|| {
            panic!("{rel} does not declare keeps_xattrs, so the {scheme} row is unchecked")
        });
        let body = &text[at..(at + 120).min(text.len())];
        let declares_false = body.contains("false");
        assert_eq!(
            row.xattrs,
            !declares_false,
            "describe says {scheme} xattrs={} while {rel} declares keeps_xattrs {}",
            row.xattrs,
            if declares_false { "false" } else { "true" }
        );
        checked += 1;
    }
    assert_eq!(
        checked, 6,
        "every listed adapter must be checked, not skipped"
    );

    // The control: the scan must be able to FAIL. A row flipped in a copy of the table
    // has to disagree with the same source it just agreed with.
    let row = SCHEMES.iter().find(|s| s.name == "s3").unwrap();
    assert!(!row.xattrs, "the s3 row is the one this control depends on");
    let text =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/s3/client.rs")).unwrap();
    let at = text.find("fn keeps_xattrs").unwrap();
    assert!(
        text[at..at + 120].contains("false"),
        "if s3 ever carries xattrs this arm's control is stale, not passing"
    );
}
