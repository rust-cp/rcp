use std::collections::BTreeMap;
use std::env;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use rcp::anytree::{AnyTree, Transports};
use rcp::catalog::{Catalog, JobLog, JobRecord, Kind, NoCatalog, Recorder};
use rcp::cluster::{self, Fleet};
use rcp::filter::{parse_age_ns, parse_kinds, parse_size, Filter};
use rcp::json::quote;
use rcp::names;
use rcp::plan::Mode;
use rcp::ports::{Log, Runtime};
#[cfg(feature = "s3")]
use rcp::s3::config::S3Options;
use rcp::scan::{self, ScanOptions};
use rcp::transfer::{
    self, Change, CopyOptions, CopyReport, DeleteOptions, Engine, EstimateOptions, Ownership,
    VerifyOptions,
};
use rcp::tree::Tree;
use rcp::zipfile::ZipWriter;
use rcp::{check_distinct_endpoints, human_bytes, Endpoint};
use std::sync::Arc;

const USAGE: &str = "\
rcp (Rust copy): a data mover for local paths (file:///path or /path), NFS exports
(host:/export, host:/export:/subdir, nfs://host/export) reached with the built-in NFSv3
client (no mount, no root, many requests in flight per connection), S3 buckets
(s3://bucket/prefix) reached with the built-in S3 client (see S3 below), and HDFS paths
(hdfs://namenode:9870/path, or hdfs:///path with -hdfs.namenode HOST:PORT or HDFS_NAMENODE)
reached over WebHDFS with pseudo authentication (HADOOP_USER_NAME) or SPNEGO against a
Kerberos-secured namenode.

  rcp copy     [copy options] [-newid ID | -noId] SOURCE DESTINATION
  rcp resume   [copy options] -id ID
  rcp sync     [copy options] -id ID [-snap PATH]
  rcp sync dry-run -id ID [-target] [-l | -v | -q]     what sync would do; -target checks the
                                                     destination against the index
  rcp isync    [copy options] SOURCE DESTINATION        incremental, no catalog
  rcp isync estimate SOURCE DESTINATION | -id ID       time for the next isync
  rcp verify   [-parallel N] [-nodata] [-noattrs] [-noown] [-nomods] [-mtimewindow S]
               [-noxattr] [-nolinks] [filters] [-v | -l] [-csv] [-stats] SOURCE DESTINATION
  rcp scan     [-parallel N] [-l] [-q] [-stats] [-csv] [-html] [-fmt TEMPLATE] [-du | -duk]
               [-depth N] [-sha256|-blake3|-xxh3|-xxh128] [-hashcache] [-edupe] [-nonames]
               [-newid ID] [filters] SOURCE
  rcp scan     -id ID [same report options]            reports from a saved scan
  rcp PATH                                             the same as scan PATH
  rcp estimate [-parallel N] [-sample BYTES] [-gbit N] [-target DIR -t DURATION] SOURCE
  rcp estimate -id SCANID [-gbit N]                    static estimate from a saved scan
  rcp delete   [-parallel N] [-force] [-removetopdir] [filters] PATH
  rcp chown    [-parallel N] [-v] [filters] (-user U [-group G] | -reference PATH
               | UID[:GID]) [-user-from U] [-group-from G] PATH
  rcp chmod    [-parallel N] [-v] [filters] (-mode MODE | -reference PATH | MODE) PATH
  rcp show     [-all] [-v]              mounted filesystems (network types by default)
  rcp show     HOST... [-v]             a server's RPC services and NFS exports (-v: sizes)
  rcp indexlist | indexdelete (-id ID | -match GLOB) | logdump [ID | -id ID]
  rcp diag     (-cat | -mkdir | -rmdir | -rmrf) PATH | -rmid ID      file utilities
  rcp diag nio [-read | -write | -read% N] [-random | -sequential | -rand% N] [-t SECS]
               [-bs SIZE] [-size SIZE] [-parallel N] [-npend N] [-wrdata] PATH   I/O generator
  rcp diag find (-branch-match GLOB | -top-match GLOB) [filters] [-l | -q] [-fmt T] PATH
  rcp diag change (-u USER | -g GROUP | -umap CSV | -gmap CSV | -atime T | -mtime T)
               [filters] [-depth N] [-v] PATH
  rcp diag indexdiag -id ID [-rebuild] [-replace] | diag rebuild -id ID | diag dump [-n N]
  rcp help [filters] | version

filters: -match GLOB / -exclude GLOB (repeatable; * ? [a-c] **)  -minsize SIZE
  -maxsize SIZE  -newer AGE (modified within, e.g. 7d)  -older AGE (modified before)
  -type f|d|l  -uid USER  -gid GROUP  -fileid INODE   (rcp help filters for examples)

copy options: -parallel N (default: CPUs, 2 to 8) or -parallel auto[:N] (an online tuner
  moves three counts within 1..N, 32 by default, by the throughput gradient: the workers in
  flight, and how many of them may be inside a read and inside a write. Separating the last
  two is what lets a contended sink settle narrower than the source it is fed from, which
  one worker count cannot express)  filters  -depth N  -bs SIZE (block size,
  default 1m)  -engine auto|uring|threads  -dryrun (plan and report, write nothing)
  -progress / -noprogress (a line every 5 s on stderr; default on when stderr is a terminal)
  -json (the run's events on stdout, one JSON object per line; every human line moves to
  stderr, so stdout parses whole -- see `rcp help info`, MACHINE-READABLE OUTPUT)
  -allow ROOT (repeatable; every endpoint must be inside one)  -readonly (refuse every
  command that writes)  -confirm DIGEST / -requireconfirm (a run that would remove or
  overwrite needs the digest a dry run printed) -- see `rcp help info`, RAILS
  -nohash (no SHA-256 in the catalog; the kernel copies the bytes)  -nolinks (copy hard
  links as files)  -noxattr (skip extended attributes and ACLs)  -chown (ownership must be
  preserved: fail otherwise)  -noown (never touch ownership)  -preserve-atime  -fsync
  (per file; default is one flush per job)  -nocache (drop copied data from the page cache)
  -nodes h1,h2,... (spread the file batches over worker hosts reached with ssh, which need
  rcp on PATH and the same endpoints; localhost runs a worker here)  -copybatch 'PROG ARGS'
  (a program standing in for the worker; rcp help info describes the line protocol)

-bwlimit RATE (64m, 1g, 500k/s) caps the bytes read from sources per second across every
worker and engine, for copy, sync, verify and scan alike. -delta sends a file the
destination already has (64 KiB or more) as a patch against it: the destination signs
its copy in content-defined chunks, the source sends only the chunks it lacks, and the
rebuilt file replaces the old one once its digest checks; over ssh:// both halves run
where the bytes are, so only signatures and changed chunks cross. -compress asks an
ssh:// far side for LZ4 on the data payloads, block by block: a block is probed on its
first 64 KiB and goes raw when that does not shrink, and a stream of such blocks stops
being probed for a while, so already-compressed data costs almost nothing extra;
-compress.codec deflate or zstd trades CPU for ratio; -compress.level 1..9 (default 6) says how
much, on both sides. -loglevel DEBUG writes one line per event on stderr (endpoints opened, a server's ports
and programs, every S3 and HDFS request with its status, every worker launched); INFO, the
default, writes none. -dircount SIZE (default 64k) is the READDIRPLUS request size on an
export. -md5 checksums the files like -sha256; the digest is SHA-256 unless -blake3 asks for
BLAKE3 (several times faster per core, parallel over 1 KiB chunks; not a FIPS digest), which
also names the digest column of -csv. Accepted for
compatibility and without effect: -nonames on commands without listings, -preserve-atime
on commands that only read (sources are opened with O_NOATIME). POSIX ACLs are carried
wherever the attribute channel is on -- as attributes locally, through the NFSACL program
on an export -- so -noxattr and -noattrs drop them with everything else in that channel.
-acl4 adds NFSv4 ACLs (system.nfs4_acl) on exports, read and written over NFSv4 beside
the v3 data path; a server without v4 is refused. -nfs.vers 3|4 (or RCP_NFS_VERS,
default 3) is the protocol the data moves over: v3 through MOUNT and READDIRPLUS, or
NFSv4.0 (RFC 7530) through COMPOUND with a client ID, open state and lease renewal, where
owners travel as user@domain (RCP_NFS4_DOMAIN names the domain; unmapped names become
nobody). -acl4 rides either.
-nfs.sec sys|krb5|krb5i|krb5p (or RCP_NFS_SEC) is the security every export is
reached with: AUTH_SYS, or Kerberos through
the host's GSSAPI library and ticket cache (kinit first), with the body checksummed (krb5i)
or encrypted (krb5p). RCP_NFS_PORT, RCP_MOUNT_PORT and RCP_NFSACL_PORT bypass the portmapper. scan takes -nodes too (one subtree per worker). HDFS keeps times to the
millisecond, has no hard links (-nolinks) and refuses symlinks on every current release.

ssh://[user@]host[:port]/path reaches a directory on a host that has rcp: the endpoint
opens `ssh host rcp serve` (RCP_SSH names another command, -rcp.remote PATH another rcp)
and everything a local path can do happens there, through OpenSSH's own keys, agent,
jump hosts and multiplexing. One ssh session per worker; reads and writes are pipelined
and holes cross the wire as lengths. `rcp serve` is that far end.

rcp://host:port/path reaches the SAME serve without ssh, over a socket that
`rcp serve -listen ADDR` is already holding. No child process and no handshake per
channel, which is what `-nodes` and `-via` want when something else already carries the
authentication -- a tunnel, a VPN, a unix-domain forward.

  BUT: ssh authenticates the peer before a frame moves, and a socket authenticates
  nobody. So `-listen` refuses to start without -allow (or RCP_ALLOWED_ROOTS) naming
  what it may serve, and refuses any address that is not loopback unless MUTUAL TLS
  authenticates the peer. An rcp endpoint takes no user (there is nothing to check one
  against) and no default port (there is none to guess).

rcps://host:port/path is that socket inside TLS. The serve presents -tls.cert with
-tls.key, and -tls.clientca names the authority that must have signed the CLIENT's
certificate; the client presents its own with the same two options and checks the
serve against -tls.ca (the system bundle by default). Only the client-certificate half
lets a serve bind a routable address: a server certificate alone encrypts the stream
without establishing who connected, which is the thing loopback was standing in for.
Needs a build with --features rustls.
sftp://[user@]host[:port]/path reaches a directory on a host that has only OpenSSH: the
endpoint opens `ssh host -s sftp` and speaks SFTP version 3, with reads and writes
pipelined. What SFTP cannot carry: inode numbers (a hard link is copied as a file),
nanosecond times (whole seconds), holes (runs of zeros are detected and skipped) and
extended attributes.

smb://[user@]host[:port]/share[/path] is a Windows, Samba or NAS share over SMB2
(dialects 0x0202 through 0x0300, NTLMv2). The first path component is the share, which
TREE_CONNECT takes; the rest is a path inside it. The credential is -smb.user
[DOMAIN\\]USER:PASSWORD or RCP_SMB_USER with RCP_SMB_PASSWORD, never the URL -- an
endpoint reaches the job log, a report and ps. What a share cannot carry: POSIX modes and
owners (verify says they were not compared rather than comparing an invented 0644),
symlinks and hard links (both refused by name; the core copies the file instead), extended
attributes, and a hole map (runs of zeros are detected and skipped, as on sftp).
Modification times DO cross, both ways. chmod and chown refuse before walking a tree they
could not change, and that refusal also stops `diag change -mtime`, which SMB2 could in
fact do. Message signing IS done -- HMAC-SHA256 on 0x0202 and 0x0210, AES-CMAC on 0x0300 --
whenever the server's negotiate response says it requires it, which current Windows and a
domain-member Samba do by default. That bit arrives before anything is authenticated, so
-smb.sign (or RCP_SMB_SIGN=1) makes this client insist on signing whatever the server
says: an on-path edit that clears the bit is then refused instead of obeyed. A handshake runs on a 10 s deadline rather than the data
path's 60 s, and -smb.handshake SECONDS (or RCP_SMB_HANDSHAKE) raises it for a link where
ten is not enough.

oci://host[:port]/repository[:tag] is a container registry's repository, seen as an
OCI image layout (oci-layout, index.json, blobs/sha256/<digest>): every tag, or the one
named. A copy between two registries mirrors the image the way skopeo and crane do, a
copy to a directory writes a layout skopeo's oci: transport reads, a copy from one pushes
it. Blobs the destination already holds are not read from the source; manifests are
pushed, children first, when the copy finishes. docker.io is Docker Hub. -oci.insecure
uses http; -oci.noverify skips certificate checks; credentials are -oci.user
USER:PASSWORD, RCP_OCI_USER with RCP_OCI_PASSWORD, or the container tools' own files
(REGISTRY_AUTH_FILE, ~/.docker/config.json). A registry keeps no times, modes or owners
(verify with -nomods).

S3: credentials and region come from AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY /
AWS_SESSION_TOKEN / AWS_REGION, else from the profile (-s3.profile NAME, AWS_PROFILE) in
~/.aws/credentials and ~/.aws/config. -s3.endpoint URL (or AWS_ENDPOINT_URL) names a
MinIO, ONTAP or other service, addressed path-style; without one the bucket is on AWS.
-s3.insecure uses http when the endpoint names no scheme; -s3.noverify skips certificate
checks (AWS_CA_BUNDLE names a private CA). Modification times, modes and owners travel
as user metadata (mtime, mode, uid, gid) so a tree round-trips; the bucket has no hard
links (-nolinks) and no extended attributes. HTTPS_PROXY / NO_PROXY are honored.

The catalog (one directory per copy ID, used by resume and sync, plus jobs.log) lives at
-catalog DIR, else $RCP_CATALOG, else $XDG_STATE_HOME/rcp/catalog, else
~/.local/state/rcp/catalog.

Every command ends with STATUS: PASSED or STATUS: FAILED and exits 0 or 1 to match.
Problems are reported on lines starting with ERROR:. With -json those lines go to stderr
and stdout carries the events instead.";

const FILTERS_HELP: &str = "\
FILTERS

Patterns match the path relative to the tree root (dir/sub/file.txt). A pattern without
a slash also matches the last component. -match keeps, -exclude drops; both repeat.

  rcp scan -match '*.txt' /data                  files ending in .txt, at any depth
  rcp scan -match 'logs/**' -exclude '*.gz' /data     everything under logs/ except .gz
  rcp copy -exclude '.snapshot' -exclude '*.tmp' /src /dst
  rcp scan -match 'f0[0-4]?.dat' /data           character classes and single characters

Predicates apply to files (directories are still walked so their children can match):

  rcp scan -minsize 100m /data                   files of at least 100 MiB
  rcp scan -maxsize 0 -l /data                   empty files
  rcp scan -newer 30m /data                      modified in the last 30 minutes
  rcp copy -older 1y /archive /cold              untouched for a year
  rcp scan -type f -uid root -stats /data        regular files owned by root
  rcp delete -force -type l /links               only symlinks
  rcp scan -l -fileid 671907 /data               the entry with that inode number

Sizes take k, m, g, t (binary); ages take s, m, h, d, w.";

const INFO_HELP: &str = "\
RCP INFO: how it works and how to tune it

ENDPOINTS
  /path or file:///path         a local or mounted directory
  host:/export[:/sub]           an NFS export, reached with the built-in NFSv3 client
  ip1,ip2:/export               the same export through several server addresses
  nfs://host/export             the same, URL style
  s3://bucket[/prefix]          an S3 bucket (see rcp help, S3)
  hdfs://namenode:port/path     an HDFS path over WebHDFS (hdfs:///path with -hdfs.namenode)
  ssh://[user@]host/path        a directory on a host with rcp (rcp serve over ssh)
  rcp://host:port/path          the same, over a socket a `serve -listen` is holding
  rcps://host:port/path         the same socket inside TLS (-tls.cert, -tls.key, -tls.ca)
  sftp://[user@]host/path       a directory on a host with only OpenSSH
  smb://[user@]host/share/path  a Windows, Samba or NAS share over SMB2 (-smb.user)
  oci://host/repository[:tag]   a container registry repository as an OCI image layout
  dav://host[:port]/path        a WebDAV collection (davs:// for TLS)
  -via ssh://[user@]host[:port] open every remote endpoint through the rcp serve on
                                that host, with the host's own credentials and settings
  Any endpoint can be the source or the destination of any command, except where a
  transport's own model forbids it: a registry holds no symlinks, hard links, modes or
  owners, and cannot be a -nodes destination; a tar stream is written once through and
  cannot be modified afterwards. Each refuses by name. `rcp describe` has the table.

PARALLELISM
  -parallel N sets the worker count (default: CPUs, 2 to 8). Each worker walks directories
  from a shared queue and copies files; on the local adapter with io_uring each worker also
  keeps up to 16 files in flight (one under -bwlimit, where the rate is the limit). Raise it
  for a filer or an object store, where latency is the limit; lower it for a single spinning
  disk, where it is not.

BLOCK SIZE AND ENGINES
  -bs SIZE (default 1m) is the read/write unit. -engine uring is the default where the
  kernel allows it and threads elsewhere; -nohash lets the kernel copy the bytes
  (copy_file_range) when no digest is wanted. Sparse files stay sparse on every engine.

NFS
  Readers keep 8 READs in flight and writers 16 UNSTABLE WRITEs, committed once per file;
  every worker holds its own connection. RCP_NFS_PORT and RCP_MOUNT_PORT bypass the
  portmapper; RCP_PORTMAP_PORT moves the portmapper itself. rcp show HOST lists what a
  server offers before a copy is planned.

S3
  Objects up to 64 MiB go as one PUT, larger ones as multipart uploads sized for the
  service's 10,000-part limit. Listing costs one HEAD per object for the POSIX metadata.
  Credentials: AWS_* variables, then the profile files. TLS needs a build with the tls
  feature; -s3.insecure selects http.

CATALOG AND RESUME
  Every completed entry is appended to the catalog as it finishes, so a killed copy leaves a
  truthful index and resume finishes the job; sync uses the same index to find changes.
  -catalog DIR, $RCP_CATALOG or $XDG_STATE_HOME/rcp/catalog set its location.

JOBS: A RUN THAT OUTLIVES THE CALL THAT STARTED IT
  `rcp job start copy -newid ID SOURCE DESTINATION` runs the command in a session of its
  own and returns a job id at once. The command after `start` is taken verbatim, so its
  options are its own. `status`, `wait`, `log` and `cancel` work from that id afterwards,
  from any process, including one started later.

  Nothing here is a daemon: the job is the ordinary command with its events going to a
  file, in its own session so a closing terminal does not take it with it. `job log -n
  OFFSET` reads forward from where the last read stopped and never hands over half a line.
  A canceled job leaves its catalog, and `rcp resume -id ID` finishes what it started.

AN AGENT HOST: rcp mcp
  `rcp mcp` serves JSON-RPC 2.0 on stdio, one message per line: initialize, ping,
  tools/list and tools/call. The tools are rcp_plan, rcp_copy, rcp_isync, rcp_verify,
  rcp_scan, rcp_count, rcp_delete, rcp_show and rcp_describe, and each returns the -json
  events of the run it made.

  Every call runs rcp itself as a child, so it gets the same argument parsing and the same
  rails a person gets, and a copy that dies takes nothing with it. Whatever the server was
  started with (-allow, -readonly) reaches every call, and -requireconfirm is added whether
  or not it was asked for: a call that would remove or overwrite is refused until its
  `confirm` carries the digest rcp_plan (or rcp_count) returned for the same endpoints and
  options. A call's `options` are checked against this build's own option tables, so it
  cannot invent an option, smuggle an endpoint through them, or set the rails itself.

RAILS, FOR A CALLER THAT IS A PROGRAM
  Three bounds, all off by default, because a person at a terminal should not have to ask
  twice. A caller that drives rcp on someone's behalf sets them and then cannot exceed
  them, whatever it was told to do.

  -allow ROOT, repeatable, else RCP_ALLOWED_ROOTS (comma-separated: commas, not colons,
  because every endpoint scheme has a colon in it). Every endpoint of the run must be the
  root or lie under it, on a path boundary, so /data does not admit /database. A local
  root never admits a remote endpoint and the reverse. The check happens before anything
  is opened, so a refused endpoint costs no connection and learns nothing about the far
  side.

  -readonly, else RCP_READONLY. Every command that writes is refused before it starts.
  Which commands write is the table `rcp describe` publishes, so the two cannot disagree.

  -confirm DIGEST and -requireconfirm, else RCP_REQUIRE_CONFIRM. A run that would remove
  or overwrite anything is refused unless -confirm carries the digest that a dry run of
  the same command printed on its `plan:` line (for delete, the counting run without
  -force). The digest covers the two endpoints and every planned action, so a tree that
  changed since the plan was read no longer matches, and the plan has to be read: the
  refusal deliberately does not name the digest it wanted.

MACHINE-READABLE OUTPUT (-json)
  stdout carries one JSON object per line and nothing else; every human line, STATUS
  included, moves to stderr. The exit code is unchanged: 0 for PASSED, 1 for FAILED.

  event      when                          fields
  entry      a file, directory or symlink  path, kind (f|d|l), size, mtime_ns, mode, and
             completed                     digest when the run hashed it
  removed    sync removed an entry         path
  difference verify found one              kind, path, detail
  warning    something worth saying        message
  error      an entry or the run failed    code, message, and op and path for an entry
  done       the command ended             status (passed|failed), command, and that
                                           command's counts

  An error's code is one of: notfound, permission, exists, unsupported, invalid, timeout,
  interrupted, disconnected, unreachable, nospace, wouldblock, io, owner (ownership could
  not be preserved and -chown made that an error), usage (the arguments, an option or an
  endpoint's shape). The set is closed: a kind with no name of its own reports io.

  scan emits an entry per item only when a listing was asked for (-l, -csv, -html, -fmt);
  without one it emits the summary alone, since a scan of a large tree is the listing.

VERIFY
  Bytes are compared, not digests; the first differing offset is reported. A destination
  whose mtime nanoseconds are zero on a matching second is tolerated with one warning;
  -mtimewindow makes the comparison strict within a window.

CLUSTER MODE
  -nodes h1,h2 hands the file batches (balanced by size) to `rcp copybatch` workers started
  over ssh on each host, which need rcp on PATH and the same source and destination
  reachable (an export or a bucket is shared by nature; a local path must be the same mount
  everywhere). Directories, links, metadata and the catalog stay with the coordinator, so
  resume and sync work as usual. RCP_SSH names the ssh program. -copybatch 'PROG ARGS' runs
  PROG instead of rcp on every node with SOURCE DESTINATION appended, NUL-separated paths
  relative to the source on stdin, and one line per path expected on stdout:
    ok<TAB>PATH<TAB>BYTES<TAB>SHA256-or-empty<TAB>OWNER-REFUSED(0|1)<TAB>XATTRS-REFUSED
    fail<TAB>PATH<TAB>MESSAGE
  scan -nodes lists the top level here and one top-level subtree per worker.

FILTERS
  rcp help filters lists the glob, size, age, type, owner and inode predicates.";

/// `-json`: the run's events go to stdout as one JSON object per line, and every human
/// line moves to stderr, so a caller can parse stdout whole. Set once by `main` before any
/// output; a process-wide flag because `fail` and `pass` are reached from everywhere and
/// threading a handle through every command would say nothing more.
static JSON: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn json_on() -> bool {
    JSON.load(std::sync::atomic::Ordering::Relaxed)
}

/// A human line: stdout normally, stderr under `-json`.
macro_rules! say {
    ($($arg:tt)*) => {{ if crate::json_on() { eprintln!($($arg)*) } else { crate::out(format_args!("{}\n", format_args!($($arg)*))) } }};
}

macro_rules! sayp {
    ($($arg:tt)*) => {{ if crate::json_on() { eprint!($($arg)*) } else { crate::out(format_args!($($arg)*)) } }};
}

/// Everything the run prints to stdout goes through here. A reader that has gone away
/// (`rcp scan X | head`) ends the run quietly, with the status a SIGPIPE death gives, which is
/// what a pipeline expects.
///
/// SIGPIPE itself stays ignored, as Rust leaves it. It used to be put back to its default so
/// that a closed stdout ended the run, and that also killed the run whenever an `ssh` child
/// died under an sftp:// or ssh:// transfer: no error, no STATUS line, and a file left half
/// written under its final name. A closed pipe to a child is a failure to report; a closed
/// stdout is the reader saying it has seen enough. Only stdout gets the second reading.
fn out(args: fmt::Arguments<'_>) {
    let mut o = io::stdout().lock();
    if let Err(e) = io::Write::write_fmt(&mut o, args) {
        rcp::exit_if_reader_left(&e);
        panic!("failed printing to stdout: {e}");
    }
}

/// One JSON object, built field by field. Numbers and booleans are written as they are,
/// strings are quoted; nothing else is accepted, so a field can never be malformed.
struct Obj(String);

impl Obj {
    fn new(event: &str) -> Obj {
        Obj(format!("{{\"event\":{}", quote(event)))
    }
    fn s(mut self, key: &str, value: impl AsRef<str>) -> Obj {
        self.0
            .push_str(&format!(",{}:{}", quote(key), quote(value.as_ref())));
        self
    }
    fn n(mut self, key: &str, value: impl fmt::Display) -> Obj {
        self.0.push_str(&format!(",{}:{value}", quote(key)));
        self
    }
    fn b(mut self, key: &str, value: bool) -> Obj {
        self.0.push_str(&format!(",{}:{value}", quote(key)));
        self
    }
    /// An array of strings, always written even when empty: a caller that branches on it
    /// should not have to tell "no skipped checks" from "this rcp is too old to say".
    fn list(mut self, key: &str, values: &[&str]) -> Obj {
        let items: Vec<String> = values.iter().map(|v| quote(v)).collect();
        self.0
            .push_str(&format!(",{}:[{}]", quote(key), items.join(",")));
        self
    }
    /// A string field only when there is one.
    fn maybe(self, key: &str, value: Option<impl AsRef<str>>) -> Obj {
        match value {
            Some(v) => self.s(key, v),
            None => self,
        }
    }
    /// Writes the line, if `-json` asked for it.
    /// Writes the line, if `-json` asked for it, and flushes. The flush is the point: to
    /// a terminal a line is written as it is made, but to a file (which is where a
    /// detached job's events go) stdout is block-buffered, so without it a caller polling
    /// `rcp job log` sees nothing until eight kilobytes of events have accumulated or the
    /// run ends. One write per completed entry is nothing beside copying the entry.
    fn emit(self) {
        if json_on() {
            out(format_args!("{}}}\n", self.0));
            if let Err(e) = io::Write::flush(&mut io::stdout()) {
                rcp::exit_if_reader_left(&e);
            }
        }
    }
}

/// The per-entry events, from the catalog's own record calls: a decorator over whatever
/// recorder the run has, so nothing in the core changes and a run without `-json` pays
/// one boolean per entry.
struct JsonRecorder<'a>(&'a mut dyn Recorder);

impl Recorder for JsonRecorder<'_> {
    fn record(&mut self, e: &rcp::catalog::Entry) -> io::Result<()> {
        Obj::new("entry")
            .s("path", &e.path)
            .s("kind", e.kind.tag())
            .n("size", e.size)
            .n("mtime_ns", e.mtime_ns)
            .n("mode", e.mode)
            .maybe(
                "digest",
                if e.sha256.is_empty() {
                    None
                } else {
                    Some(&e.sha256)
                },
            )
            .emit();
        self.0.record(e)
    }
    fn record_gone(&mut self, path: &str) -> io::Result<()> {
        Obj::new("removed").s("path", path).emit();
        self.0.record_gone(path)
    }
}

/// A command that could not start or could not finish: the message a person reads and the
/// stable code an automated caller branches on. Anything that is only a message is a
/// `usage` failure, which is what a mistyped option or a missing argument is; an endpoint
/// that could not be opened carries the code its error kind gave.
#[derive(Debug)]
struct Failed {
    message: String,
    code: &'static str,
}

impl From<String> for Failed {
    fn from(message: String) -> Failed {
        Failed {
            message,
            code: "usage",
        }
    }
}

impl From<&str> for Failed {
    fn from(message: &str) -> Failed {
        Failed {
            message: message.to_string(),
            code: "usage",
        }
    }
}

impl fmt::Display for Failed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Failed {}

impl From<Failed> for String {
    fn from(f: Failed) -> String {
        f.message
    }
}

/// A command that failed on an I/O error: the prefix a person reads, the kind's code.
fn io_failed(prefix: impl AsRef<str>, e: &io::Error) -> Failed {
    Failed {
        message: format!("{}: {e}", prefix.as_ref()),
        code: rcp::ports::code_of(e),
    }
}

fn fail(failure: impl Into<Failed>) -> ExitCode {
    let f = failure.into();
    Obj::new("error")
        .s("code", f.code)
        .s("message", &f.message)
        .emit();
    Obj::new("done").s("status", "failed").emit();
    say!("ERROR: {}", f.message);
    say!("STATUS: FAILED");
    ExitCode::from(1)
}

fn pass() -> ExitCode {
    Obj::new("done").s("status", "passed").emit();
    say!("STATUS: PASSED");
    ExitCode::SUCCESS
}

/// `pass` or `fail` without a second `done` event: the command emitted its own.
fn ended(ok: bool) -> ExitCode {
    if ok {
        say!("STATUS: PASSED");
        ExitCode::SUCCESS
    } else {
        say!("STATUS: FAILED");
        ExitCode::from(1)
    }
}

/// The transports this build speaks, named once so `version` and `describe` agree.
const TRANSPORTS: &str = if cfg!(windows) {
    if cfg!(all(
        feature = "s3",
        feature = "smb",
        feature = "dav",
        feature = "https"
    )) {
        if cfg!(feature = "rustls") {
            "local, s3 (http and https), smb, dav (http and https), http and https (indexed reads)"
        } else {
            "local, s3 (http only), smb, dav (http only), http (indexed reads); TLS requires --features rustls"
        }
    } else {
        "local; additional Windows adapters depend on enabled Cargo features: s3, smb, dav, https"
    }
} else if cfg!(feature = "rustls") {
    "local, tar (ustar + pax), ssh (rcp serve), rcp (a listening rcp serve, loopback only), rcps (the same over TLS; mutual TLS lifts loopback), sftp (OpenSSH subsystem, v3), nfs (v3, v4.0; sys, krb5, krb5i, krb5p), hdfs (webhdfs, pseudo or spnego), s3 (http and https), oci (http and https), dav (http and https)"
} else {
    "local, tar (ustar + pax), ssh (rcp serve), rcp (a listening rcp serve, loopback only; rcps:// needs a build with --features rustls), sftp (OpenSSH subsystem, v3), nfs (v3, v4.0; sys, krb5, krb5i, krb5p), hdfs (webhdfs, pseudo or spnego), s3 (http only; https needs a build with --features rustls), oci (http only; https needs a build with --features rustls), dav (http only; davs:// needs a build with --features rustls)"
};

/// Options that take a value. Everything else that starts with `-` is a switch.
const VALUED: &[&str] = &[
    "parallel",
    "newid",
    "id",
    "catalog",
    "match",
    "exclude",
    "minsize",
    "maxsize",
    "newer",
    "older",
    "type",
    "uid",
    "gid",
    "fileid",
    "bs",
    "mtimewindow",
    "depth",
    "dircount",
    "loglevel",
    "engine",
    "nfs.sec",
    "nfs.vers",
    "bwlimit",
    "sample",
    "fmt",
    "snap",
    "user",
    "group",
    "user-from",
    "group-from",
    "reference",
    "mode",
    "gbit",
    "t",
    "m",
    "j",
    "nodes",
    "copybatch",
    "rcp.remote",
    "s3.endpoint",
    "s3.profile",
    "oci.user",
    "dav.user",
    "smb.user",
    "smb.handshake",
    "http.user",
    "http.index",
    "via",
    "allow",
    "confirm",
    "compress.codec",
    "compress-codec",
    "compress.level",
    "tls.ca",
    "tls.cert",
    "tls.key",
    "tls.clientca",
    "rmrf",
    "cat",
    "mkdir",
    "rmdir",
    "rmid",
    "n",
    "rand%",
    "listen",
    "read%",
    "npend",
    "size",
    "u",
    "g",
    "umap",
    "gmap",
    "atime",
    "mtime",
    "top-match",
    "branch-match",
    "hdfs.namenode",
];
const SWITCHES: &[&str] = &[
    "h",
    "help",
    "version",
    "V",
    "noid",
    "preserve-atime",
    "chown",
    "noown",
    "noxattr",
    "nolinks",
    "nohash",
    "fsync",
    "nocache",
    "acl4",
    "md5",
    "sha256",
    "blake3",
    "xxh3",
    "xxh128",
    "delta",
    "compress",
    "nodata",
    "noattrs",
    "nomods",
    "v",
    "l",
    "q",
    "stats",
    "csv",
    "du",
    "duk",
    "edupe",
    "hashcache",
    "rsyncable",
    "force",
    "removetopdir",
    "nonames",
    "html",
    "dryrun",
    "progress",
    "noprogress",
    "all",
    "s3.insecure",
    "s3.noverify",
    "oci.insecure",
    "oci.noverify",
    "dav.insecure",
    "dav.noverify",
    "http.noverify",
    "smb.sign",
    "json",
    "readonly",
    "requireconfirm",
    "read",
    "write",
    "random",
    "sequential",
    "wrdata",
    "rebuild",
    "replace",
];

struct Args {
    /// The ports assembled from the options: the run's digest, throttle, log and names.
    runtime: Runtime,
    /// How each kind of remote endpoint is reached in this run.
    transports: Transports,
    command: String,
    /// A word after the command that selects a mode: `dry-run`, `estimate`, `filters`, `info`.
    sub: Option<String>,
    positional: Vec<String>,
    values: BTreeMap<String, Vec<String>>,
    switches: Vec<String>,
}

impl Args {
    fn has(&self, s: &str) -> bool {
        self.switches.iter().any(|x| x == s)
    }
    fn value(&self, k: &str) -> Option<&str> {
        self.values
            .get(k)
            .and_then(|v| v.last())
            .map(String::as_str)
    }
    fn all(&self, k: &str) -> Vec<String> {
        self.values.get(k).cloned().unwrap_or_default()
    }
    /// `-parallel N`, or the ceiling of `-parallel auto[:N]` (32 unless N says otherwise).
    fn parallel(&self) -> Result<usize, String> {
        match self.value("parallel") {
            None => Ok(std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(2)
                .clamp(2, 8)),
            Some("auto") => Ok(32),
            Some(v) if v.starts_with("auto:") => match v[5..].parse::<usize>() {
                Ok(0) => Err("-parallel auto:N needs N of at least 1".into()),
                Ok(n) => Ok(n),
                Err(_) => Err(format!("-parallel {v:?}: use auto or auto:N")),
            },
            Some(v) => match v.parse::<usize>() {
                Ok(0) => Err("-parallel must be at least 1".into()),
                Ok(n) => Ok(n),
                Err(_) => Err(format!("-parallel {v:?} is not a number (or auto, auto:N)")),
            },
        }
    }
    fn parallel_auto(&self) -> bool {
        self.value("parallel")
            .is_some_and(|v| v == "auto" || v.starts_with("auto:"))
    }
    fn depth(&self) -> Result<Option<usize>, String> {
        self.value("depth")
            .map(|v| {
                v.parse::<usize>()
                    .map_err(|_| format!("-depth {v:?} is not a number"))
            })
            .transpose()
    }
    fn block_size(&self) -> Result<usize, String> {
        let Some(v) = self.value("bs") else {
            return Ok(1 << 20);
        };
        let bytes = parse_size(v).map_err(|e| format!("-bs {e}"))? as usize;
        if !(4096..=1 << 30).contains(&bytes) {
            return Err("-bs must be between 4k and 1g".into());
        }
        Ok(bytes)
    }
    fn filter(&self) -> Result<Filter, String> {
        let size = |k: &str| {
            self.value(k)
                .map(|v| parse_size(v).map_err(|e| format!("-{k} {e}")))
                .transpose()
        };
        let age = |k: &str| {
            self.value(k)
                .map(|v| parse_age_ns(v).map_err(|e| format!("-{k} {e}")))
                .transpose()
        };
        let uid = self
            .value("uid")
            .map(|v| {
                names::uid_of(v).ok_or_else(|| format!("-uid {v:?}: not a number or a known user"))
            })
            .transpose()?;
        let gid = self
            .value("gid")
            .map(|v| {
                names::gid_of(v).ok_or_else(|| format!("-gid {v:?}: not a number or a known group"))
            })
            .transpose()?;
        Ok(Filter {
            include: self.all("match"),
            exclude: self.all("exclude"),
            min_size: size("minsize")?,
            max_size: size("maxsize")?,
            newer_than_ns: age("newer")?,
            older_than_ns: age("older")?,
            kinds: self.value("type").map(parse_kinds).transpose()?,
            uid,
            gid,
            fileid: self
                .value("fileid")
                .map(|v| {
                    v.parse::<u64>()
                        .map_err(|_| format!("-fileid {v:?}: not an inode number"))
                })
                .transpose()?,
        })
    }
    fn progress(&self) -> bool {
        self.has("progress") || (!self.has("noprogress") && rcp::stderr_is_tty())
    }
    fn engine(&self) -> Result<Engine, String> {
        match self.value("engine").unwrap_or("auto") {
            "auto" => Ok(Engine::Auto),
            "uring" | "io_uring" => Ok(Engine::Uring),
            "threads" => Ok(Engine::Threads),
            other => Err(format!("-engine {other:?}: use auto, uring or threads")),
        }
    }
    fn copy_options(&self) -> Result<CopyOptions, String> {
        if self.has("chown") && self.has("noown") {
            return Err("-chown and -noown contradict each other".into());
        }
        Ok(CopyOptions {
            runtime: self.runtime.clone(),
            parallel: self.parallel()?,
            auto_parallel: self.parallel_auto(),
            filter: self.filter()?,
            max_depth: self.depth()?,
            dry_run: self.has("dryrun") || self.sub.as_deref() == Some("dry-run"),
            dry_run_target: self.has("target"),
            dry_run_stats: self.has("stats"),
            progress: self.progress(),
            hash: !self.has("nohash"),
            hard_links: !self.has("nolinks"),
            xattrs: !self.has("noxattr"),
            ownership: if self.has("chown") {
                Ownership::Require
            } else if self.has("noown") {
                Ownership::Skip
            } else {
                Ownership::Preserve
            },
            preserve_atime: self.has("preserve-atime"),
            fsync: self.has("fsync"),
            block_size: self.block_size()?,
            nocache: self.has("nocache"),
            engine: self.engine()?,
            delta: self.has("delta"),
            fleet: None,
            confirm: self.value("confirm").map(str::to_string),
            require_confirm: self.has("requireconfirm")
                || env::var("RCP_REQUIRE_CONFIRM").is_ok_and(|v| !v.is_empty()),
        })
    }
    /// The options a worker process on another node must see: everything about how a file
    /// is copied or listed, nothing about this run's identity (catalog, ids, dry runs).
    /// The options a fleet node needs, and the environment to hand it beside them.
    ///
    /// `LOCAL` is a DENY-list, which is the right shape for "this option is about this
    /// process" and the wrong shape for a credential: it had no credential names in it, so
    /// `-dav.user alice:PASSWORD` went onto the command line of every host in `-nodes`,
    /// where it sat on each one's `ps` for the length of the copy. A deny-list fails OPEN,
    /// and the option that is missing from it is always the one added last.
    ///
    /// So credentials are asked about by capability rather than by name, and travel in the
    /// environment -- the same split `rcp mcp` and `rcp job` make, for the same reason. One
    /// that has no environment reader stays an argument rather than being dropped: a
    /// credential silently discarded is a node that runs unauthenticated.
    fn forward_args(&self) -> (Vec<String>, Vec<(String, String)>) {
        const LOCAL: &[&str] = &[
            "nodes",
            "copybatch",
            "newid",
            "id",
            "catalog",
            "snap",
            "target",
            "progress",
            "noprogress",
            "dryrun",
            "noid",
            "q",
            "l",
            "v",
            "stats",
            "csv",
            "html",
            "fmt",
            "du",
            "duk",
            "edupe",
        ];
        let mut out = Vec::new();
        #[allow(unused_mut)]
        let mut env: Vec<(String, String)> = Vec::new();
        for (k, vs) in &self.values {
            if LOCAL.contains(&k.as_str()) {
                continue;
            }
            if rcp::describe::capability_of(k) == Some(rcp::describe::Capability::Credential) {
                #[cfg(unix)]
                if let Some(var) = rcp::mcp::relay_env(k) {
                    for v in vs {
                        env.push((var.to_string(), v.clone()));
                    }
                    continue;
                }
            }
            for v in vs {
                out.push(format!("-{k}"));
                out.push(v.clone());
            }
        }
        for s in &self.switches {
            if !LOCAL.contains(&s.as_str()) {
                out.push(format!("-{s}"));
            }
        }
        (out, env)
    }
    /// `-nodes h1,h2` (and/or `-copybatch PROG`): the worker fleet for a copy.
    fn fleet(&self, source: &str, destination: &str) -> Result<Option<Fleet>, String> {
        #[cfg(windows)]
        if self.value("nodes").is_some() || self.value("copybatch").is_some() {
            return Err("Windows worker fleets are unsupported until process-tree cancellation is qualified".into());
        }
        let nodes: Vec<String> = self
            .value("nodes")
            .map(|v| {
                v.split(',')
                    .map(str::trim)
                    .filter(|n| !n.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        let copybatch = self.value("copybatch").map(str::to_string);
        if self.value("nodes").is_some() && nodes.is_empty() {
            return Err("-nodes needs a comma-separated list of hosts".into());
        }
        if nodes.is_empty() && copybatch.is_none() {
            return Ok(None);
        }
        let nodes = if nodes.is_empty() {
            vec!["localhost".to_string()]
        } else {
            nodes
        };
        let (forward, env) = self.forward_args();
        // A credential can reach a LOCAL worker safely, through its environment. It cannot
        // reach a remote one: ssh carries a command line, and anything this run puts in it
        // -- including an `env VAR=secret rcp ...` prefix -- is on that host's `ps` for the
        // length of the copy. Forwarding it anyway is the defect this refusal replaces;
        // dropping it silently is worse, because the node then runs unauthenticated and
        // reports its failures as the far end's. So the operator is told, by name, and
        // pointed at the channel that does work.
        if !env.is_empty() {
            if let Some(remote) = nodes
                .iter()
                .find(|n| n.as_str() != "localhost" && n.as_str() != "local")
            {
                let names: Vec<&str> = env.iter().map(|(k, _)| k.as_str()).collect();
                return Err(format!(
                    "a credential option cannot be forwarded to the remote node {remote:?}: ssh would put it on that host's command line, where every user on it can read it. Set {} in the environment on each node instead, and leave the option off this run",
                    names.join(", ")
                ));
            }
        }
        Ok(Some(Fleet {
            nodes,
            copybatch,
            forward,
            env,
            source: source.to_string(),
            destination: destination.to_string(),
            log: self.runtime.log.clone(),
        }))
    }
    /// The `-s3.*` options, installed for every `s3://` endpoint of the run.
    #[cfg(feature = "s3")]
    fn s3_options(&self) -> S3Options {
        S3Options {
            endpoint: self.value("s3.endpoint").map(str::to_string),
            profile: self.value("s3.profile").map(str::to_string),
            insecure: self.has("s3.insecure"),
            noverify: self.has("s3.noverify"),
        }
    }
}

fn parse_args(raw: Vec<String>) -> Result<Args, String> {
    let mut command: Option<String> = None;
    let mut sub = None;
    let mut positional = Vec::new();
    let mut values: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut switches = Vec::new();
    let mut it = raw.into_iter().peekable();
    while let Some(a) = it.next() {
        let flag = a.trim_start_matches('-');
        let is_flag =
            a.starts_with('-') && !flag.is_empty() && !flag.chars().all(|c| c.is_ascii_digit());
        if !is_flag {
            match &command {
                None => {
                    // `rcp /path` is `rcp scan /path`
                    if a.starts_with('/') || a.starts_with("file://") {
                        command = Some("scan".into());
                        positional.push(a);
                    } else {
                        command = Some(a);
                    }
                }
                Some(c)
                    if sub.is_none()
                        && positional.is_empty()
                        && matches!(
                            (c.as_str(), a.as_str()),
                            ("sync", "dry-run")
                                | ("isync", "estimate")
                                | ("help", "filters")
                                | ("help", "info")
                                | ("license", "update")
                                | (
                                    "diag",
                                    "dump" | "nio" | "indexdiag" | "find" | "change" | "rebuild"
                                )
                                | (
                                    "job",
                                    "start"
                                        | "list"
                                        | "status"
                                        | "wait"
                                        | "cancel"
                                        | "log"
                                        | "forget"
                                )
                        ) =>
                {
                    sub = Some(a)
                }
                _ => positional.push(a),
            }
            continue;
        }
        let key = match flag {
            "noId" => "noid".to_string(),
            other => other.to_string(),
        };
        // -target is a path for estimate and a switch for sync dry-run: a following token that
        // is not an option is its value.
        if key == "target" {
            match it.peek() {
                Some(next) if !next.starts_with('-') => {
                    let v = it.next().unwrap_or_default();
                    values.entry(key).or_default().push(v);
                }
                _ => switches.push(key),
            }
            continue;
        }
        if VALUED.contains(&key.as_str()) {
            // `rcp help -match` asks for the filter examples
            if it.peek().is_none() && command.as_deref() == Some("help") {
                switches.push(key);
                continue;
            }
            let v = it.next().ok_or_else(|| format!("-{key} needs a value"))?;
            values.entry(key).or_default().push(v);
        } else if SWITCHES.contains(&key.as_str()) {
            switches.push(key);
        } else {
            return Err(format!("unknown option -{flag}"));
        }
    }
    let command = if switches.iter().any(|s| s == "h" || s == "help") {
        "help".to_string()
    } else if switches.iter().any(|s| s == "version" || s == "V") {
        "version".to_string()
    } else {
        command.unwrap_or_else(|| "help".into())
    };
    Ok(Args {
        runtime: Runtime::plain(),
        transports: Transports::from_env(Arc::new(rcp::ports::Silent)),
        command,
        sub,
        positional,
        values,
        switches,
    })
}

/// The catalog directory: explicit flag, then $RCP_CATALOG, then the XDG state directory.
fn catalog_dir(explicit: Option<&str>) -> PathBuf {
    if let Some(p) = explicit {
        return PathBuf::from(p);
    }
    if let Ok(p) = env::var("RCP_CATALOG") {
        if !p.is_empty() {
            return Endpoint::parse(&p)
                .map(|e| e.path)
                .unwrap_or_else(|_| PathBuf::from(p));
        }
    }
    if let Ok(state) = env::var("XDG_STATE_HOME") {
        if !state.is_empty() {
            return Path::new(&state).join("rcp/catalog");
        }
    }
    let home = env::var("HOME")
        .ok()
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "/var/lib".into());
    Path::new(&home).join(".local/state/rcp/catalog")
}

fn endpoints(positional: &[String], what: &str) -> Result<(Endpoint, Endpoint), String> {
    if positional.len() != 2 {
        return Err(format!(
            "{what} takes exactly SOURCE and DESTINATION, got {}",
            positional.len()
        ));
    }
    let src = Endpoint::parse(&positional[0]).map_err(|e| e.to_string())?;
    let dst = Endpoint::parse(&positional[1]).map_err(|e| e.to_string())?;
    check_distinct_endpoints(&src, &dst)?;
    Ok((src, dst))
}

/// Values of `-{name}` in a raw argv, using the same "this option takes a value" list the
/// parser uses so a later flag is not read as a value.
fn option_values(argv: &[String], name: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < argv.len() {
        let arg = &argv[i];
        let bare = arg.trim_start_matches('-');
        let takes = arg.starts_with('-') && VALUED.contains(&bare);
        if bare == name && arg.starts_with('-') {
            if let Some(v) = argv.get(i + 1) {
                out.push(v.clone());
            }
        }
        i += 1;
        if takes {
            i += 1;
        }
    }
    out
}

/// A child job inherits the rails of the process that started it. `-allow` on this
/// command line is not in the child's argv, and the child would otherwise copy anywhere.
/// A child `-allow` that climbs out of those roots is refused. `-requireconfirm` is
/// added when this process has it, including via `RCP_REQUIRE_CONFIRM`.
fn forward_job_rails(args: &Args, command: &mut Vec<String>) -> Result<(), Failed> {
    let parent = allowed_roots(args);
    if !parent.is_empty() {
        let child = option_values(command, "allow");
        if child.is_empty() {
            let mut injected = Vec::with_capacity(command.len() + parent.len() * 2);
            for root in &parent {
                injected.push("-allow".into());
                injected.push(root.clone());
            }
            injected.append(command);
            *command = injected;
        } else {
            for c in &child {
                let inside = parent.iter().any(|p| root_within(c, p));
                if !inside {
                    return Err(Failed {
                        message: format!(
                            "job start: -allow {c} is outside the roots this run may touch ({})",
                            parent.join(", ")
                        ),
                        code: "permission",
                    });
                }
            }
        }
    }
    let confirm =
        args.has("requireconfirm") || env::var("RCP_REQUIRE_CONFIRM").is_ok_and(|v| !v.is_empty());
    if confirm && !command.iter().any(|a| a == "-requireconfirm") {
        command.insert(0, "-requireconfirm".into());
    }
    Ok(())
}

fn root_within(child: &str, parent: &str) -> bool {
    let local = |r: &str| !r.contains("://");
    if !local(child) || !local(parent) {
        return under(child.trim_end_matches('/'), parent.trim_end_matches('/'));
    }
    let c = real_path(Path::new(child)).display().to_string();
    let p = real_path(Path::new(parent)).display().to_string();
    under(&c, &p)
}

/// The roots this run may touch: `-allow` (repeatable), else `RCP_ALLOWED_ROOTS` split on
/// commas. Empty means no restriction, which is what a person at a terminal gets; a caller
/// that is a program sets one and then cannot reach outside it.
///
/// Commas, not the colon a `PATH` uses: a root may be an endpoint, and every endpoint
/// scheme has a colon in it. Splitting on colons turned `ssh://host/path` into the two
/// roots `ssh` and `//host/path`, which admitted neither the endpoint it named nor
/// anything else. A test control caught it.
fn allowed_roots(args: &Args) -> Vec<String> {
    // `/` is a root that admits every local path, and it has to survive the trimming that
    // makes `/data/` and `/data` the same root: trimmed to nothing and then dropped as
    // empty, `-allow /` used to leave NO roots at all, which is a rail that is not there.
    let clean = |r: &str| -> Option<String> {
        let r = r.trim();
        match r.trim_end_matches('/') {
            "" if r.starts_with('/') => Some("/".to_string()),
            "" => None,
            trimmed => Some(trimmed.to_string()),
        }
    };
    let mut roots: Vec<String> = args.all("allow").iter().filter_map(|r| clean(r)).collect();
    if roots.is_empty() {
        if let Ok(v) = env::var("RCP_ALLOWED_ROOTS") {
            roots = v.split(',').filter_map(clean).collect();
        }
    }
    roots
}

/// Whether `text` is `root` or lies under it. The boundary matters: `/data` must not
/// admit `/database`, which a bare prefix test would.
fn under(text: &str, root: &str) -> bool {
    if root == "/" {
        return text.starts_with('/');
    }
    text == root
        || text
            .strip_prefix(root)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// The path a local endpoint really names: every symlink followed and every `..` applied,
/// as far as the path exists, with what does not exist yet appended.
///
/// A spelling check is not containment, and both ways out were measured before this was
/// here. With `-allow /data`, `/data/../secret` passed the rail and its file was copied;
/// so did `/data/link` with `link` a symlink to anywhere. Components are resolved from the
/// root outwards, each existing one canonicalized before the next is applied, because that
/// is the order the kernel resolves them in: `a/b/..` is not `a` when `b` is a symlink.
/// Symlinks *inside* a tree need no such care — a copy recreates them and never follows
/// one.
fn real_path(p: &Path) -> PathBuf {
    let abs = std::path::absolute(p).unwrap_or_else(|_| p.to_path_buf());
    let mut left: Vec<std::ffi::OsString> = abs
        .components()
        .rev()
        .filter_map(|c| match c {
            std::path::Component::Normal(name) => Some(name.to_os_string()),
            std::path::Component::ParentDir => Some(std::ffi::OsString::from("..")),
            _ => None,
        })
        .collect();
    let mut out = PathBuf::from("/");
    // a bounded number of links, as the kernel does: a loop must end in a decision
    let mut hops = 0;
    while let Some(name) = left.pop() {
        if name == ".." {
            out.pop();
            continue;
        }
        out.push(&name);
        match out.canonicalize() {
            Ok(real) => out = real,
            Err(_) => {
                // canonicalize fails for a path that does not exist AND for a symlink
                // whose target does not. Treating both as "take the spelling" is failing
                // OPEN: `-allow /data` would admit /data/out when out is a dangling link
                // to /secret/new, and a create follows that link. Read the link and carry
                // on with what it names; only a path with no link left is taken as spelled.
                if let Ok(target) = fs::read_link(&out) {
                    hops += 1;
                    if hops > 40 {
                        return out;
                    }
                    out.pop();
                    let target = if target.is_absolute() {
                        out = PathBuf::from("/");
                        target
                    } else {
                        target
                    };
                    for c in target.components().rev() {
                        match c {
                            std::path::Component::Normal(n) => left.push(n.to_os_string()),
                            std::path::Component::ParentDir => {
                                left.push(std::ffi::OsString::from(".."))
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
    }
    out
}

/// Refuses an endpoint outside the allowed roots, before anything is opened, so a refused
/// endpoint costs no connection and reveals nothing about the far side. A local endpoint
/// is compared by its absolute path and a remote one by the text it prints as, which is
/// what a root like `oci://registry.example` or `s3://bucket/prefix` names.
fn allowed(args: &Args, ep: &Endpoint) -> Result<(), Failed> {
    let roots = allowed_roots(args);
    if roots.is_empty() {
        return Ok(());
    }
    let shown = ep.display();
    // A remote path cannot be resolved from here -- only the far side knows what its
    // symlinks and `..` mean -- so an endpoint that climbs is refused rather than compared
    // as text. Most schemes refuse `..` when they parse it; this closes the rest.
    // the comparison below is against the text an endpoint prints as, so it is that text
    // that must not climb -- for NFS the `..` lands in the export rather than the path,
    // and a check that looked only at the path would miss it
    if !ep.is_local() && (shown.contains("/../") || shown.ends_with("/..")) {
        return Err(Failed { message: format!("{shown}: a path with `..` in it cannot be checked against the roots this run may touch, because only the far side can resolve it"), code: "permission" });
    }
    let local = if ep.is_local() {
        real_path(&ep.path).display().to_string()
    } else {
        String::new()
    };
    let ok = roots.iter().any(|r| {
        if ep.is_local() {
            // a scheme-qualified root never admits a local path, and the reverse; the root
            // is resolved the same way the endpoint is, or a root that is itself a symlink
            // (/var/tmp on many systems) would admit nothing
            !r.contains("://")
                && under(
                    &local,
                    &real_path(Path::new(r.strip_prefix("file://").unwrap_or(r)))
                        .display()
                        .to_string(),
                )
        } else {
            under(&shown, r)
        }
    });
    if ok {
        Ok(())
    } else {
        Err(Failed {
            message: format!(
                "{shown} is outside the roots this run may touch ({})",
                roots.join(", ")
            ),
            code: "permission",
        })
    }
}

/// Refuses a command that writes when `-readonly` (or `RCP_READONLY`) is set. Which
/// commands write is the same table `rcp describe` publishes, so the two cannot disagree.
/// Refuses the options that hand the run to another program when any rail is set. Which
/// options: the ones `describe` classifies as running something, so this list cannot drift
/// from the one the MCP server reads. Which rails: `-allow`, `-readonly` and
/// `-requireconfirm` all describe a run someone else is driving, and all three are
/// worthless beside a program the run will execute. Measured through `rcp mcp` with two
/// allowed roots and `-copybatch 'touch /tmp/x'`: the file appeared.
fn options_allowed(args: &Args) -> Result<(), Failed> {
    let railed = !allowed_roots(args).is_empty()
        || args.has("readonly")
        || env::var("RCP_READONLY").is_ok_and(|v| !v.is_empty())
        || args.has("requireconfirm")
        || env::var("RCP_REQUIRE_CONFIRM").is_ok_and(|v| !v.is_empty());
    if !railed {
        return Ok(());
    }
    for (name, cap, _) in rcp::describe::OPTIONS.iter() {
        let Some(why) = cap.why_not_railed() else {
            continue;
        };
        if args.values.contains_key(*name) {
            // The environment is a real route for these two and not a blanket one, which
            // is what this used to imply. `RCP_S3_ENDPOINT`, `RCP_S3_PROFILE`,
            // `RCP_HDFS_NAMENODE` and `RCP_OCI_USER` are read; a `Runs` option has no
            // variable and never will, because the point of refusing it is that no rail
            // bounds a program this run starts.
            let route = match *cap {
                rcp::describe::Capability::Service | rcp::describe::Capability::Credential => "; set it in the environment instead, which is where the operator who set the rails sets it",
                _ => "",
            };
            return Err(Failed { message: format!("-{name} {why}, which no rail can bound; it cannot be used on a run that has one{route}"), code: "permission" });
        }
    }
    Ok(())
}

/// Where a registry may hand this run's uploads on to, from the same roots `-allow` uses.
///
/// A registry answers the upload `POST` with a `Location` that may name another host --
/// ECR and GAR front object storage that way -- and the bytes of every blob then go there.
/// An unrailed run follows it: naming the registry is already a statement of trust in it.
/// A railed one follows it only to an authority its own roots name, because `-allow` is
/// the operator saying where this run's data may go, and the far end is not the operator.
///
/// A root's authority is its `scheme://host:port`, with the scheme's default port filled
/// in, so `-allow https://storage.example` and a `Location` on `https://storage.example:443`
/// are the same place. A root with no scheme is a local path and names no authority.
fn away_policy(args: &Args) -> Result<rcp::ports::Away, Failed> {
    let roots = allowed_roots(args);
    if roots.is_empty() {
        return Ok(rcp::ports::Away::Anywhere);
    }
    let mut authorities: Vec<String> = Vec::new();
    for root in &roots {
        let Some((scheme, rest)) = root.split_once("://") else {
            continue;
        };
        let host = rest.split('/').next().unwrap_or("");
        if host.is_empty() {
            continue;
        }
        // Not `.parse().ok()`, which would undo the rule the comment below states.
        // `"99999"` is all digits, so it takes this branch, then fails to fit a u16 and
        // becomes `None` -- which `port.unwrap_or(..)` fills in with the scheme's DEFAULT.
        // So `-allow https://host:99999` would admit `https://host:443`, a place the
        // operator never named, silently, in the one direction a rail must
        // never move. Every other authority reader in this crate refuses `99999` by name;
        // this one has to as well, because a rail that widens on a typo is worse than a
        // rail that refuses to start.
        let (host, port) = match host.rsplit_once(':') {
            Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() => match p.parse::<u16>() {
                Ok(n) => (h, Some(n)),
                Err(_) => return Err(Failed::from(format!("-allow {root}: port {p:?} is not a number, and a root this run cannot read is not a root it may widen to the scheme's default"))),
            },
            _ => (host, None),
        };
        // `oci` is rcp's spelling of an endpoint, never a scheme on the wire: the wire is
        // http under `-oci.insecure` and https otherwise, and an authority written `oci://`
        // can match no `Location` at all. So a root is translated to the scheme it will
        // really be spoken in, at the port it named -- or that scheme's default when it
        // named none.
        //
        // An explicitly named port is never rewritten, even when it happens to be 80 or
        // 443: `-allow oci://host:80` turned into `https://host:443` would admit a place
        // the operator did not name and refuse the one they did. A port the operator
        // wrote is the port, whatever it is.
        // `-oci.insecure` is not the only way to ask for plain HTTP: `RCP_OCI_INSECURE`
        // does it too, and reading only the switch would make the policy disagree with
        // the wire on an env-configured run -- a false denial of a hand-off that is fine.
        // It is the same shape as the port bug beside it: deriving a fact from one of the
        // two places that carry it.
        let insecure =
            args.has("oci.insecure") || env::var("RCP_OCI_INSECURE").is_ok_and(|v| !v.is_empty());
        // A root whose scheme is never spoken on an HTTP wire names no authority a
        // `Location` or a realm could ever match, and emitting one (`s3://bucket:443`)
        // is a dead entry that only makes the list harder to read.
        if !matches!(scheme, "oci" | "hdfs" | "http" | "https") {
            continue;
        }
        // `hdfs` is rcp's spelling too, and WebHDFS is spoken over plain HTTP unless the
        // namenode was named `https://...` -- in which case the root is written that way
        // and takes the `https` branch below. A root left at `hdfs://` therefore names an
        // http authority, which is what a datanode `Location` from such a cluster carries.
        let wire = match scheme {
            "oci" if insecure => "http",
            "oci" => "https",
            "hdfs" => "http",
            other => other,
        };
        let port = port.unwrap_or(if wire == "http" { 80 } else { 443 });
        authorities.push(format!("{wire}://{host}:{port}"));
    }
    Ok(rcp::ports::Away::Only(authorities.into()))
}

fn writes_allowed(args: &Args) -> Result<(), Failed> {
    let readonly = args.has("readonly") || env::var("RCP_READONLY").is_ok_and(|v| !v.is_empty());
    if !readonly {
        return Ok(());
    }
    if let Some(what) = writes_because_of_its_arguments(args) {
        return Err(Failed {
            message: format!("{what}, and this run is read-only"),
            code: "permission",
        });
    }
    match rcp::describe::COMMANDS
        .iter()
        .find(|c| c.name == args.command)
    {
        Some(c) if c.writes => Err(Failed {
            message: format!("{} writes, and this run is read-only", args.command),
            code: "permission",
        }),
        _ => Ok(()),
    }
}

/// Commands whose write-ness is decided by their ARGUMENTS rather than their name, and
/// what each one writes.
///
/// `describe::COMMANDS` is keyed by name and says `writes: false` for all three, which is
/// true of the bare command and false of the form with the argument. Finding one of these
/// is how the other two turned up, which is the argument for one list rather than three
/// conditions scattered through `run`:
///
/// - `logdump ID` writes `ID.zip` into the working directory. Measured: `-readonly logdump
///   demo` reported PASSED with demo.zip on disk.
/// - `scan -newid ID` writes a catalog. Measured: `-readonly scan -newid s1` reported
///   PASSED and created it.
/// - `estimate -target DIR` copies a live sample into `DIR` to time it, then removes it.
///   Measured: `-readonly estimate -target ...` reported PASSED having written and deleted
///   a file under a directory this run was told not to touch. That it cleans up afterwards
///   is not the point -- a read-only run wrote.
fn writes_because_of_its_arguments(args: &Args) -> Option<String> {
    match args.command.as_str() {
        "logdump" if logdump_id(args).is_some() => Some("logdump ID writes ID.zip".into()),
        "scan" if args.value("newid").is_some() => Some("scan -newid writes a catalog".into()),
        "estimate" if args.value("target").is_some() => {
            Some("estimate -target copies a live sample into the target".into())
        }
        _ => None,
    }
}

/// The ID `logdump` was given, if any. One place, because two readings of it is how the
/// rail and the write came to disagree about whether there was one.
fn logdump_id(args: &Args) -> Option<String> {
    args.value("id")
        .or(args.value("m"))
        .or(args.value("j"))
        .map(String::from)
        .or_else(|| args.positional.first().cloned())
}

fn open_tree(args: &Args, ep: &Endpoint) -> Result<AnyTree, Failed> {
    allowed(args, ep)?;
    AnyTree::open(ep, false, &args.transports).map_err(|e| Failed {
        message: format!("{}: {e}", ep.display()),
        code: rcp::ports::code_of(&e),
    })
}

/// A destination: a missing path inside an NFS export is created, as a local one would be.
fn open_destination(args: &Args, ep: &Endpoint) -> Result<AnyTree, Failed> {
    allowed(args, ep)?;
    AnyTree::open(ep, true, &args.transports).map_err(|e| Failed {
        message: format!("{}: {e}", ep.display()),
        code: rcp::ports::code_of(&e),
    })
}

/// Endpoints recorded in a catalog come back as the text they were given as.
fn endpoint_of(path: &Path) -> Result<Endpoint, String> {
    Endpoint::parse(&path.to_string_lossy()).map_err(|e| e.to_string())
}

fn one_endpoint(positional: &[String], what: &str) -> Result<Endpoint, String> {
    match positional {
        [p] => Endpoint::parse(p).map_err(|e| e.to_string()),
        _ => Err(format!(
            "{what} takes exactly one path, got {}",
            positional.len()
        )),
    }
}

fn rate(bytes: u64, seconds: f64) -> String {
    if seconds <= 0.0 {
        return "-".into();
    }
    format!("{}/s", human_bytes((bytes as f64 / seconds) as u64))
}

/// `30s`, `5m`, `2h`; a bare number is seconds.
fn parse_duration(text: &str) -> Result<f64, String> {
    parse_age_ns(text).map(|ns| ns as f64 / 1e9)
}

struct Job<'a> {
    root: PathBuf,
    command: &'a str,
    id: String,
    source: String,
    destination: String,
    started: Instant,
}

impl Job<'_> {
    fn log(&self, status: &str, summary: &str) {
        let r = JobRecord {
            command: self.command,
            id: &self.id,
            source: &self.source,
            destination: &self.destination,
            status,
            seconds: self.started.elapsed().as_secs_f64(),
            summary,
        };
        if let Err(e) = JobLog::append(&self.root, &r) {
            eprintln!(
                "WARN: jobs.log not written under {}: {e}",
                self.root.display()
            );
        }
    }
}

fn report_copy(args: &Args, job: &Job<'_>, report: &mut CopyReport, verb: &str) -> ExitCode {
    let mut summary = format!(
        "{} files ({} bytes), {} skipped, {} directories, {} symlinks, {} removed, {} linked, {} moved",
        report.copied_files, report.copied_bytes, report.skipped_files, report.directories, report.symlinks, report.removed, report.linked, report.moved
    );
    if !report.deferred.is_empty() {
        summary.push_str(&format!(", {} deferred", report.deferred.len()));
    }
    if !report.kept.is_empty() {
        summary.push_str(&format!(", {} kept", report.kept.len()));
    }
    // the same three things `delete` says -- the count, a line per entry, and an event
    // per entry -- so the copy path does not report only the first
    for d in &report.deferred {
        Obj::new("deferred").s("path", d).emit();
        say!("DEFERRED: {d}");
    }
    for k in &report.kept {
        Obj::new("kept").s("path", k).emit();
        say!("KEPT: {k}");
    }
    if report.delta_files > 0 {
        summary.push_str(&format!(
            "; delta: {} files, {} literal bytes",
            report.delta_files, report.delta_literal
        ));
    }
    if report.dry_run {
        if !args.has("q") {
            for line in &report.planned {
                say!("{line}");
            }
        }
        for line in &report.target_mismatches {
            say!("{line}");
        }
        if let Some(stats) = &report.planned_stats {
            sayp!("{stats}");
        }
        say!("{verb} (dry run, nothing written): {summary}");
        if !report.plan_digest.is_empty() {
            say!("plan: {}", report.plan_digest);
        }
        if !report.target_mismatches.is_empty() {
            report.failures.push(rcp::ports::Failure::of(
                "target",
                "destination",
                "changed",
                format!(
                    "{} index entries no longer match the destination",
                    report.target_mismatches.len()
                ),
            ));
        }
    } else {
        say!(
            "{verb}: {summary}; engine {}, {:.2} s, {}",
            report.engine,
            report.seconds,
            rate(report.copied_bytes, report.seconds)
        );
    }
    for w in &report.warnings {
        Obj::new("warning").s("message", w).emit();
        say!("WARN: {w}");
    }
    for f in &report.failures {
        Obj::new("error")
            .s("code", f.code)
            .s("op", f.op)
            .s("path", &f.path)
            .s("message", &f.message)
            .emit();
        say!("ERROR: {f}");
    }
    Obj::new("done")
        .s("status", if report.ok() { "passed" } else { "failed" })
        .s("command", verb)
        .b("dry_run", report.dry_run)
        .n("files", report.copied_files)
        .n("bytes", report.copied_bytes)
        .n("skipped", report.skipped_files)
        .n("directories", report.directories)
        .n("symlinks", report.symlinks)
        .n("removed", report.removed)
        .n("deferred", report.deferred.len())
        .n("kept", report.kept.len())
        .n("linked", report.linked)
        .n("moved", report.moved)
        .n("delta_files", report.delta_files)
        .n("delta_literal", report.delta_literal)
        .maybe(
            "plan",
            if report.plan_digest.is_empty() {
                None
            } else {
                Some(&report.plan_digest)
            },
        )
        .n("failed", report.failures.len())
        .s("engine", report.engine)
        .n("seconds", format!("{:.3}", report.seconds))
        .emit();
    if report.ok() {
        job.log("PASSED", &summary);
        ended(true)
    } else {
        // Two different failures with two different remedies. A failed entry is
        // finished by `resume`, which re-plans the copy. A KEPT entry is a removal the
        // store refused, and `resume` never plans removals -- only `sync` does -- so
        // the advice for one was wrong for the other, and "0 entries failed" was
        // printed for a run that failed on kept entries alone.
        // And a FAILED REMOVAL is not finished by `resume` either, for the same reason a
        // kept one is not: `resume` re-plans the COPY and never plans removals (the
        // planner's own arm says so). The line below said "use resume" for every failure
        // regardless of what it was, so a run that failed on an EROFS destination, a DAV
        // 507 or an `rmdir` of a directory a kept child still occupies was sent to a
        // command that could not finish it. The `Kept` category narrowed the set that got
        // unusable advice; it did not empty it.
        let (gone_wrong, copy_wrong): (Vec<_>, Vec<_>) = report
            .failures
            .iter()
            .partition(|f| matches!(f.op, "remove" | "rmdir"));
        // And the third case the two above still got wrong: a run with NO CATALOG. `-noid`,
        // a dry run, and a bare `isync` all record nothing, so `job.id` is "-" and there is
        // nothing for `resume` to open. Sending an operator to `rcp resume -id -` is the
        // same class of unusable advice as sending a failed sweep there: the command cannot
        // do the thing the sentence promises.
        if !copy_wrong.is_empty() {
            let n = copy_wrong.len();
            if job.id == "-" {
                say!("ERROR: {n} entries failed; this run kept no catalog, so run {verb} again once the cause is fixed");
            } else if rcp::describe::sweeps(verb) {
                say!("ERROR: {n} entries failed; the catalog keeps what completed, but run the same {verb} again to finish it (`resume` does not plan removals, so it cannot)");
            } else {
                say!("ERROR: {n} entries failed; the catalog keeps what completed: `rcp resume -id {}` finishes it", job.id);
            }
        }
        if !gone_wrong.is_empty() {
            say!("ERROR: {} removals failed; run {verb} again once the cause is fixed (`resume` re-plans the copy and never plans removals, so it cannot finish these)", gone_wrong.len());
        }
        if !report.kept.is_empty() {
            say!("ERROR: {} entries refused by the store are still there; run {verb} again once they can be removed", report.kept.len());
        }
        job.log(
            "FAILED",
            &format!(
                "{summary}, {} failed, {} kept",
                report.failures.len(),
                report.kept.len()
            ),
        );
        ended(false)
    }
}

fn run_copy(args: &Args, mode: Mode, root: &Path) -> ExitCode {
    let mut opts = match args.copy_options() {
        Ok(o) => o,
        Err(e) => return fail(e),
    };
    match mode {
        Mode::Fresh | Mode::Mirror => {
            let (src, dst) = match endpoints(&args.positional, &args.command) {
                Ok(v) => v,
                Err(e) => return fail(e),
            };
            opts.fleet = match args
                .fleet(&src.display(), &dst.display())
                .map(|f| f.map(|f| Arc::new(f) as Arc<dyn rcp::ports::Batches>))
            {
                Ok(f) => f,
                Err(e) => return fail(e),
            };
            let (stree, dtree) = match (
                open_tree(args, &src),
                if opts.dry_run {
                    open_tree(args, &dst)
                } else {
                    open_destination(args, &dst)
                },
            ) {
                (Ok(s), Ok(d)) => (s, d),
                (Err(e), _) | (_, Err(e)) => return fail(e),
            };
            let no_catalog = args.has("noid")
                || opts.dry_run
                || (mode == Mode::Mirror && args.value("newid").is_none());
            let id = if no_catalog {
                "-".to_string()
            } else {
                args.value("newid")
                    .or(args.value("id"))
                    .map(String::from)
                    .unwrap_or_else(|| {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_nanos())
                            .unwrap_or(0);
                        format!("copy-{now}")
                    })
            };
            let job = Job {
                root: root.to_path_buf(),
                command: &args.command,
                id: id.clone(),
                source: src.display(),
                destination: dst.display(),
                started: Instant::now(),
            };
            let mut catalog: Box<dyn Recorder> = if no_catalog {
                Box::new(NoCatalog)
            } else {
                match Catalog::create(
                    root,
                    &id,
                    Path::new(&src.display()),
                    Path::new(&dst.display()),
                    args.runtime.digests.name(),
                ) {
                    Ok(c) => {
                        say!("catalog: {} (id {id})", c.dir.display());
                        Box::new(c)
                    }
                    Err(e) => return fail(e.to_string()),
                }
            };
            let mut events;
            let recorder: &mut dyn Recorder = if json_on() {
                events = JsonRecorder(catalog.as_mut());
                &mut events
            } else {
                catalog.as_mut()
            };
            match transfer::copy_tree(&stree, &dtree, mode, None, recorder, &opts) {
                Ok(mut r) => report_copy(args, &job, &mut r, &args.command),
                Err(e) => {
                    job.log("FAILED", &e.to_string());
                    fail(io_failed(&args.command, &e))
                }
            }
        }
        Mode::Resume | Mode::Sync => {
            let Some(id) = args.value("id") else {
                return fail(format!("{} needs -id ID", args.command));
            };
            let mut catalog = match Catalog::open(root, id) {
                Ok(c) => c,
                Err(e) => return fail(e.to_string()),
            };
            // A catalog's digest column holds hex and one algorithm's worth of meaning.
            // Continuing it under a different algorithm leaves a MIXTURE -- measured:
            // `copy -newid m -blake3` then `sync -id m` put a BLAKE3 digest on one file
            // and a SHA-256 digest on another, in the same column, with nothing to tell
            // them apart. `scan -edupe` groups by that column and `sync`'s move detection
            // carries it forward, so the mixture is not inert. Refuse and name the flag,
            // rather than silently rehashing the whole tree or silently mixing.
            if let Some(was) = catalog.digest.clone() {
                let now = args.runtime.digests.name();
                if was != now {
                    return fail(format!(
                        "catalog {id} was written with {was} and this run uses {now}; the digest column would hold both. Re-run with -{was}, or start a new catalog with -newid"
                    ));
                }
            } else {
                // Written before the algorithm was recorded, so it is genuinely unknown
                // rather than assumed to be the default -- a catalog made with -blake3
                // before this existed looks exactly like one made without it.
                say!("WARN: catalog {id} predates the digest-algorithm record; if it was not written with {}, its digests and this run's will not compare", args.runtime.digests.name());
            }
            let known = match catalog.entries() {
                Ok(k) => k,
                Err(e) => return fail(format!("catalog {}: {e}", catalog.dir.display())),
            };
            let source = match args.value("snap") {
                Some(s) => match Endpoint::parse(s) {
                    Ok(e) => e,
                    Err(e) => return fail(format!("-snap: {e}")),
                },
                None => match endpoint_of(&catalog.source) {
                    Ok(e) => e,
                    Err(e) => return fail(format!("catalog source: {e}")),
                },
            };
            let destination = match endpoint_of(&catalog.destination) {
                Ok(e) => e,
                Err(e) => return fail(format!("catalog destination: {e}")),
            };
            if let Err(e) = check_distinct_endpoints(&source, &destination) {
                return fail(e);
            }
            opts.fleet = match args
                .fleet(&source.display(), &destination.display())
                .map(|f| f.map(|f| Arc::new(f) as Arc<dyn rcp::ports::Batches>))
            {
                Ok(f) => f,
                Err(e) => return fail(e),
            };
            say!(
                "catalog: {} (id {id}); source {} -> destination {}",
                catalog.dir.display(),
                source.display(),
                destination.display()
            );
            let verb = if opts.dry_run {
                format!("{} dry-run", args.command)
            } else {
                args.command.clone()
            };
            let job = Job {
                root: root.to_path_buf(),
                command: &verb,
                id: id.to_string(),
                source: source.display(),
                destination: destination.display(),
                started: Instant::now(),
            };
            let (stree, dtree) = match (
                open_tree(args, &source),
                if opts.dry_run {
                    open_tree(args, &destination)
                } else {
                    open_destination(args, &destination)
                },
            ) {
                (Ok(s), Ok(d)) => (s, d),
                (Err(e), _) | (_, Err(e)) => return fail(e),
            };
            let mut events;
            let recorder: &mut dyn Recorder = if json_on() {
                events = JsonRecorder(&mut catalog);
                &mut events
            } else {
                &mut catalog
            };
            match transfer::copy_tree(&stree, &dtree, mode, Some(&known), recorder, &opts) {
                Ok(mut r) => report_copy(args, &job, &mut r, &verb),
                Err(e) => {
                    job.log("FAILED", &e.to_string());
                    fail(io_failed(&args.command, &e))
                }
            }
        }
    }
}

/// `isync estimate`: what the next isync would move, and how long at a measured rate.
fn run_isync_estimate(args: &Args, root: &Path) -> ExitCode {
    let (source, destination) = if let Some(id) = args.value("id") {
        match Catalog::open(root, id) {
            Ok(c) => match (endpoint_of(&c.source), endpoint_of(&c.destination)) {
                (Ok(s), Ok(d)) => (s, d),
                (Err(e), _) | (_, Err(e)) => return fail(format!("catalog {id}: {e}")),
            },
            Err(e) => return fail(e.to_string()),
        }
    } else {
        match endpoints(&args.positional, "isync estimate") {
            Ok(v) => v,
            Err(e) => return fail(e),
        }
    };
    let mut opts = match args.copy_options() {
        Ok(o) => o,
        Err(e) => return fail(e),
    };
    opts.dry_run = true;
    let (stree, dtree) = match (open_tree(args, &source), open_tree(args, &destination)) {
        (Ok(s), Ok(d)) => (s, d),
        (Err(e), _) | (_, Err(e)) => return fail(e),
    };
    let plan = match transfer::copy_tree(&stree, &dtree, Mode::Mirror, None, &mut NoCatalog, &opts)
    {
        Ok(r) => r,
        Err(e) => return fail(format!("isync estimate: {e}")),
    };
    let eo = EstimateOptions {
        parallel: opts.parallel,
        filter: opts.filter.clone(),
        sample_bytes: 64 << 20,
        block_size: opts.block_size,
        gbit: 0.0,
        live_seconds: 0.0,
        runtime: args.runtime.clone(),
    };
    let est = match transfer::estimate(&stree, None, &eo) {
        Ok(e) => e,
        Err(e) => return fail(format!("isync estimate: {e}")),
    };
    let data_s = if est.read_bytes_per_s > 0.0 {
        plan.copied_bytes as f64 / est.read_bytes_per_s
    } else {
        0.0
    };
    let meta_s = (plan.copied_files + plan.removed + plan.symlinks) as f64 * 4.0
        / est.entries_per_s.max(1e-6);
    say!(
        "isync estimate: {} files ({}) to copy, {} to remove, {} unchanged",
        plan.copied_files,
        human_bytes(plan.copied_bytes),
        plan.removed,
        plan.skipped_files
    );
    say!(
        "measured: read {} at {} , scan {:.0} entries/s",
        human_bytes(est.sampled_bytes),
        rate(est.sampled_bytes, est.sample_seconds),
        est.entries_per_s
    );
    say!(
        "estimate: about {:.1} s (data {:.1} s, metadata {:.1} s) with -parallel {}",
        data_s + meta_s,
        data_s,
        meta_s,
        opts.parallel
    );
    pass()
}

fn run_verify(args: &Args, root: &Path) -> ExitCode {
    let (src, dst) = match endpoints(&args.positional, "verify") {
        Ok(v) => v,
        Err(e) => return fail(e),
    };
    let window = match args.value("mtimewindow") {
        None => None,
        Some(v) => match v.parse::<f64>() {
            Ok(s) if s >= 0.0 => Some((s * 1e9) as i128),
            _ => return fail(format!("-mtimewindow {v:?} is not a number of seconds")),
        },
    };
    let opts = VerifyOptions {
        runtime: args.runtime.clone(),
        parallel: match args.parallel() {
            Ok(p) => p,
            Err(e) => return fail(e),
        },
        filter: match args.filter() {
            Ok(f) => f,
            Err(e) => return fail(e),
        },
        max_depth: match args.depth() {
            Ok(d) => d,
            Err(e) => return fail(e),
        },
        data: !args.has("nodata"),
        mode: !args.has("noattrs"),
        owner: !args.has("noown") && !args.has("noattrs"),
        mtime: !args.has("nomods") && !args.has("noattrs"),
        mtime_window_ns: window,
        xattrs: !args.has("noxattr") && !args.has("noattrs"),
        hard_links: !args.has("nolinks"),
        block_size: match args.block_size() {
            Ok(b) => b,
            Err(e) => return fail(e),
        },
        verbose: args.has("v"),
        long: args.has("l"),
        stats: args.has("stats"),
    };
    let job = Job {
        root: root.to_path_buf(),
        command: "verify",
        id: "-".into(),
        source: src.display(),
        destination: dst.display(),
        started: Instant::now(),
    };
    let (stree, dtree) = match (open_tree(args, &src), open_tree(args, &dst)) {
        (Ok(s), Ok(d)) => (s, d),
        (Err(e), _) | (_, Err(e)) => return fail(e),
    };
    match transfer::verify_tree(&stree, &dtree, &opts) {
        Ok(r) => {
            if opts.stats && args.has("csv") {
                say!("statistic,source,destination,same");
                for line in r.verbose.iter().skip(1) {
                    let f: Vec<&str> = line.split_whitespace().collect();
                    if f.len() >= 3 {
                        let same = !line.starts_with('*');
                        say!(
                            "{},{},{},{}",
                            f[if same { 0 } else { 1 }..f.len() - 2].join(" "),
                            f[f.len() - 2],
                            f[f.len() - 1],
                            same
                        );
                    }
                }
            } else {
                for line in r.verbose.iter().chain(&r.warnings).chain(&r.long_lines) {
                    say!("{line}");
                }
                if args.has("csv") {
                    say!("kind,path,detail");
                    for d in &r.differences {
                        say!("{}", d.csv());
                    }
                } else {
                    for d in &r.differences {
                        say!("{d}");
                    }
                }
            }
            let summary = format!(
                "{} {} compared, {} bytes, {} differences, {} warnings",
                r.compared,
                if opts.stats { "statistics" } else { "entries" },
                r.bytes,
                r.differences.len(),
                r.warnings.len()
            );
            say!(
                "verify: {summary}; {:.2} s, {}",
                r.seconds,
                rate(r.bytes, r.seconds)
            );
            for d in &r.differences {
                Obj::new("difference")
                    .s("kind", d.kind)
                    .s("path", &d.path)
                    .s("detail", &d.detail)
                    .emit();
            }
            for w in &r.warnings {
                Obj::new("warning").s("message", w).emit();
            }
            Obj::new("done")
                .s("status", if r.passed() { "passed" } else { "failed" })
                .s("command", "verify")
                .n("compared", r.compared)
                .n("bytes", r.bytes)
                .n("differences", r.differences.len())
                .n("warnings", r.warnings.len())
                // A check the run was asked for and did not make is neither a difference
                // nor a warning a caller can branch on: `differences: 0` reads as "the
                // mtimes matched" when they were never compared. Always present, so an
                // empty list means "nothing skipped" rather than "too old to say".
                .list("skipped", &r.skipped)
                .n("seconds", format!("{:.3}", r.seconds))
                .emit();
            if r.passed() {
                job.log("PASSED", &summary);
                ended(true)
            } else {
                job.log("FAILED", &summary);
                say!("ERROR: destination differs from source");
                ended(false)
            }
        }
        Err(e) => {
            job.log("FAILED", &e.to_string());
            fail(io_failed("verify", &e))
        }
    }
}

fn run_scan(args: &Args, root: &Path) -> ExitCode {
    let mut opts = ScanOptions {
        runtime: args.runtime.clone(),
        parallel: match args.parallel() {
            Ok(p) => p,
            Err(e) => return fail(e),
        },
        filter: match args.filter() {
            Ok(f) => f,
            Err(e) => return fail(e),
        },
        max_depth: match args.depth() {
            Ok(d) => d,
            Err(e) => return fail(e),
        },
        hash: args.has("sha256")
            || args.has("md5")
            || args.has("blake3")
            || args.has("xxh3")
            || args.has("xxh128"),
        dedupe: args.has("edupe"),
        block_size: match args.block_size() {
            Ok(b) => b,
            Err(e) => return fail(e),
        },
        names: !args.has("nonames"),
        cache: None,
    };
    // From a saved scan (`-id`) or from the tree.
    let (s, source_text) = if let Some(id) = args.value("id") {
        let c = match Catalog::open(root, id) {
            Ok(c) => c,
            Err(e) => return fail(e.to_string()),
        };
        let entries = match c.entries() {
            Ok(e) => e,
            Err(e) => return fail(format!("catalog {}: {e}", c.dir.display())),
        };
        say!(
            "scan: saved index {id} of {} ({} entries)",
            c.source.display(),
            entries.len()
        );
        (
            scan::from_entries(
                &entries,
                if opts.names {
                    Some(args.runtime.names.clone())
                } else {
                    None
                },
                args.runtime.digests.name(),
            ),
            c.source.display().to_string(),
        )
    } else {
        let src = match one_endpoint(&args.positional, "scan") {
            Ok(e) => e,
            Err(e) => return fail(e),
        };
        let job = Job {
            root: root.to_path_buf(),
            command: "scan",
            id: args.value("newid").unwrap_or("-").into(),
            source: src.display(),
            destination: String::new(),
            started: Instant::now(),
        };
        let tree = match open_tree(args, &src) {
            Ok(t) => t,
            Err(e) => return fail(e),
        };
        let nodes: Vec<String> = args
            .value("nodes")
            .map(|v| {
                v.split(',')
                    .map(str::trim)
                    .filter(|n| !n.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        // `-hashcache`, and only with a digest asked for: a cache of digests nobody wanted
        // is a file written for nothing. Keyed by the endpoint as written AND by the digest
        // algorithm, so two algorithms over one tree are two caches -- see
        // `rcp::hashcache` for why that separation is the load-bearing part.
        //
        // Not armed for `-nodes`: each node scans its own subtree in its own process and
        // this process only stitches the answers together, so the cache here would record
        // digests for files it never looked at. Said out loud rather than silently ignored.
        if args.has("hashcache") && !opts.hash {
            // Silently doing nothing is how a flag gets believed. `-edupe` alone is not
            // covered either: it hashes only the files whose size another file shares, so
            // most paths are never asked about and a run like that must not be allowed to
            // decide what is gone.
            say!("WARN: -hashcache does nothing without a digest; add -sha256, -blake3, -xxh3 or -xxh128");
        }
        if args.has("hashcache") && opts.hash {
            if nodes.is_empty() {
                opts.cache = Some(Arc::new(std::sync::Mutex::new(
                    rcp::hashcache::HashCache::open(
                        root,
                        &src.display(),
                        args.runtime.digests.name(),
                    ),
                )));
            } else {
                say!("WARN: -hashcache is not used with -nodes; each node hashes its own subtree");
            }
        }
        let s = if nodes.is_empty() {
            match scan::scan(&tree, &opts) {
                Ok(s) => s,
                Err(e) => {
                    job.log("FAILED", &e.to_string());
                    return fail(io_failed(format!("scan {}", src.display()), &e));
                }
            }
        } else {
            // the top level here, every top-level subtree on a node
            let t0 = Instant::now();
            let top_opts = ScanOptions {
                parallel: opts.parallel,
                filter: opts.filter.clone(),
                max_depth: Some(1),
                hash: opts.hash,
                dedupe: false,
                block_size: opts.block_size,
                names: opts.names,
                cache: None,
                runtime: args.runtime.clone(),
            };
            let top = match scan::scan(&tree, &top_opts) {
                Ok(s) => s,
                Err(e) => return fail(format!("scan {}: {e}", src.display())),
            };
            let subtrees: Vec<String> = top
                .listing
                .items
                .iter()
                .filter(|i| i.kind == Kind::Dir && i.rel != ".")
                .map(|i| i.rel.clone())
                .collect();
            let (mut items, mut hashes, errors) = match cluster::scan_batches(
                &nodes,
                &args.forward_args().0,
                &src.display(),
                &subtrees,
                &*args.runtime.log,
            ) {
                Ok(v) => v,
                Err(e) => return fail(format!("scan {}: {e}", src.display())),
            };
            items.extend(top.listing.items);
            items.sort_unstable_by(|a, b| a.rel.cmp(&b.rel));
            items.dedup_by(|a, b| a.rel == b.rel);
            hashes.extend(top.hashes);
            let mut all_errors = top.listing.errors;
            all_errors.extend(errors);
            for e in &all_errors {
                say!("WARN: {e}");
            }
            scan::Scan {
                listing: rcp::tree::Listing {
                    items,
                    errors: all_errors,
                },
                hashes,
                seconds: t0.elapsed().as_secs_f64(),
                names: if opts.names {
                    Some(args.runtime.names.clone())
                } else {
                    None
                },
                hash_name: args.runtime.digests.name(),
                hashed: 0,
                cache_hits: 0,
            }
        };
        if let Some(id) = args.value("newid") {
            if s.listing.errors.is_empty() {
                let mut c = match Catalog::create(
                    root,
                    id,
                    Path::new(&src.display()),
                    Path::new("-"),
                    args.runtime.digests.name(),
                ) {
                    Ok(c) => c,
                    Err(e) => return fail(e.to_string()),
                };
                for e in scan::to_entries(&s) {
                    if let Err(err) = c.record(&e) {
                        return fail(format!("catalog {}: {err}", c.dir.display()));
                    }
                }
                say!("catalog: {} (id {id}, scan index)", c.dir.display());
            }
        }
        if let Some(cache) = &opts.cache {
            let mut c = cache.lock().unwrap();
            // A run that walked the whole tree with no filter and no depth limit knows that
            // a path it never asked about is gone; a FILTERED one knows nothing of the kind
            // and must not evict what it never looked at. `-maxdepth 1` would otherwise
            // throw away the cache for everything below it, so the next full scan pays for
            // this narrow one. An unreadable directory is the same shape: the paths under
            // it were not seen, and saving as complete would drop them from the cache.
            let complete =
                opts.filter.is_empty() && opts.max_depth.is_none() && s.listing.errors.is_empty();
            say!(
                "hashcache: {} hits, {} files read, {} entries",
                s.cache_hits,
                s.hashed,
                c.len()
            );
            if let Err(e) = c.save(complete) {
                // A cache that cannot be written is not a scan that failed. The digests are
                // right either way; the next run just pays for them again.
                say!("WARN: hashcache not saved: {e}");
            }
        }
        let sum = scan::summary(&s);
        if s.listing.errors.is_empty() {
            job.log(
                "PASSED",
                &format!(
                    "{} directories, {} files, {} symlinks, {} bytes",
                    sum.directories, sum.files, sum.symlinks, sum.bytes
                ),
            );
        } else {
            job.log(
                "FAILED",
                &format!("{} directories could not be read", s.listing.errors.len()),
            );
        }
        (s, src.display())
    };
    let quiet = args.has("q");
    if let Some(fmt) = args.value("fmt") {
        sayp!("{}", scan::format_report(&s, fmt));
    } else if args.has("html") {
        sayp!("{}", scan::html_report(&s, &source_text));
    } else if args.has("csv") {
        sayp!("{}", scan::csv_report(&s));
    } else if args.has("l") {
        sayp!("{}", scan::listing_report(&s, true));
    } else if opts.hash && !quiet {
        for (rel, h) in &s.hashes {
            say!("{h}  {rel}");
        }
    }
    if args.has("stats") {
        sayp!("{}", scan::stats_report(&s));
    }
    if args.has("du") || args.has("duk") {
        sayp!("{}", scan::du_report(&s, args.has("duk")));
    }
    if opts.dedupe {
        sayp!("{}", scan::dedupe_report(&s));
    }
    // A directory this run could not read is a directory whose contents are missing from
    // every number below. Printing those numbers under PASSED answers the question the
    // operator asked -- "what is in this tree" -- with a count that is short by an unknown
    // amount, and says it is right. Measured against a WebDAV source with one unreadable
    // subdirectory: `2 directories, 2 files` and `STATUS: PASSED`, for a tree of four
    // files. So the counts still print, because a partial answer beats none, and the
    // verdict says they are partial.
    for e in &s.listing.errors {
        say!("WARN: unreadable {e}");
    }
    let unreadable = s.listing.errors.len();
    let sum = scan::summary(&s);
    say!(
        "{} directories, {} files, {} symlinks, {} bytes; {:.2} s",
        sum.directories,
        sum.files,
        sum.symlinks,
        sum.bytes,
        s.seconds
    );
    if let Some((p, n)) = &sum.largest {
        say!("largest: {p} ({n} bytes)");
    }
    if json_on() {
        if args.has("l") || args.has("csv") || args.has("html") || args.value("fmt").is_some() {
            for i in &s.listing.items {
                Obj::new("entry")
                    .s("path", &i.rel)
                    .s("kind", i.kind.tag())
                    .n("size", i.size)
                    .n("mtime_ns", i.mtime_ns)
                    .n("mode", i.mode)
                    .n("uid", i.uid)
                    .n("gid", i.gid)
                    .maybe(
                        "digest",
                        s.hashes.iter().find(|(r, _)| **r == i.rel).map(|(_, h)| h),
                    )
                    .emit();
            }
        }
        Obj::new("done")
            .s("status", if unreadable == 0 { "passed" } else { "failed" })
            .s("command", "scan")
            .s("source", &source_text)
            .n("directories", sum.directories)
            .n("files", sum.files)
            .n("symlinks", sum.symlinks)
            .n("bytes", sum.bytes)
            .n("unreadable", unreadable)
            .n("seconds", format!("{:.3}", s.seconds))
            .emit();
        return ended(unreadable == 0);
    }
    if unreadable > 0 {
        return fail(format!(
            "{unreadable} {} could not be read, so the counts above are short by an unknown amount",
            if unreadable == 1 {
                "directory"
            } else {
                "directories"
            }
        ));
    }
    pass()
}

fn run_estimate(args: &Args, root: &Path) -> ExitCode {
    let gbit = match args.value("gbit") {
        None => 1.0,
        Some(v) => match v.parse::<f64>() {
            Ok(g) if g > 0.0 => g,
            _ => return fail(format!("-gbit {v:?} is not a positive number")),
        },
    };
    let parallel = match args.parallel() {
        Ok(p) => p,
        Err(e) => return fail(e),
    };
    // Static: from a saved scan index.
    if let Some(id) = args.value("id") {
        let c = match Catalog::open(root, id) {
            Ok(c) => c,
            Err(e) => return fail(e.to_string()),
        };
        let entries = match c.entries() {
            Ok(e) => e,
            Err(e) => return fail(format!("catalog {}: {e}", c.dir.display())),
        };
        let s = scan::from_entries(&entries, None, args.runtime.digests.name());
        let sum = scan::summary(&s);
        let e =
            transfer::estimate_static(sum.directories, sum.files, sum.symlinks, sum.bytes, gbit);
        say!(
            "index {id}: {} directories, {} files, {} symlinks, {}",
            e.directories,
            e.files,
            e.symlinks,
            human_bytes(e.bytes)
        );
        say!("estimate: best case {:.1} s at {} Gbit/s (bytes over the wire only); run against the source path with -target for a measured figure", e.gbit_seconds, e.gbit);
        return pass();
    }
    let src = match one_endpoint(&args.positional, "estimate") {
        Ok(e) => e,
        Err(e) => return fail(e),
    };
    let sample_bytes = match args.value("sample") {
        None => 256u64 << 20,
        Some(v) => match parse_size(v) {
            Ok(n) => n,
            Err(e) => return fail(format!("-sample {e}")),
        },
    };
    let live_seconds = match args.value("t") {
        None => 300.0,
        Some(v) => match parse_duration(v) {
            Ok(s) if s > 0.0 => s,
            _ => return fail(format!("-t {v:?} is not a duration (use 30s, 5m)")),
        },
    };
    let opts = EstimateOptions {
        runtime: args.runtime.clone(),
        parallel,
        filter: match args.filter() {
            Ok(f) => f,
            Err(e) => return fail(e),
        },
        sample_bytes,
        block_size: match args.block_size() {
            Ok(b) => b,
            Err(e) => return fail(e),
        },
        gbit,
        live_seconds,
    };
    // Live: a scratch directory under the intended target, removed afterwards.
    let scratch = match args.value("target") {
        Some(t) => {
            let target = match Endpoint::parse(t) {
                Ok(e) => e,
                Err(e) => return fail(format!("-target: {e}")),
            };
            let name = format!(".rcp-estimate-{}", std::process::id());
            let parent = match open_tree(args, &target) {
                Ok(t) => t,
                Err(e) => return fail(format!("-target {e}")),
            };
            if let Err(e) = parent.mkdir(&name) {
                return fail(format!("-target {}: {e}", target.display()));
            }
            let ep = target.join(&name);
            match open_tree(args, &ep) {
                Ok(t) => Some((ep, t)),
                Err(e) => return fail(e),
            }
        }
        None => None,
    };
    let stree = match open_tree(args, &src) {
        Ok(t) => t,
        Err(e) => return fail(e),
    };
    let job = Job {
        root: root.to_path_buf(),
        command: "estimate",
        id: "-".into(),
        source: src.display(),
        destination: scratch
            .as_ref()
            .map(|(ep, _)| ep.display())
            .unwrap_or_default(),
        started: Instant::now(),
    };
    let result = transfer::estimate(&stree, scratch.as_ref().map(|(_, t)| t), &opts);
    if let Some((ep, t)) = &scratch {
        let wipe = DeleteOptions {
            parallel,
            filter: Filter::default(),
            force: true,
            remove_top: true,
            confirm: None,
            require_confirm: false,
            runtime: None,
        };
        match transfer::delete_tree(t, &wipe) {
            Ok(r) if r.failures.is_empty() => {}
            Ok(r) => say!(
                "WARN: scratch directory {} not fully removed: {}",
                ep.display(),
                r.failures.join("; ")
            ),
            Err(e) => say!("WARN: scratch directory {} not removed: {e}", ep.display()),
        }
    }
    match result {
        Ok(e) => {
            say!(
                "scan: {} directories, {} files, {} symlinks, {} in {:.2} s ({:.0} entries/s)",
                e.directories,
                e.files,
                e.symlinks,
                human_bytes(e.bytes),
                e.scan_seconds,
                e.entries_per_s
            );
            say!(
                "read sample: {} files, {} in {:.2} s = {}",
                e.sampled_files,
                human_bytes(e.sampled_bytes),
                e.sample_seconds,
                rate(e.sampled_bytes, e.sample_seconds)
            );
            say!(
                "best case: {:.1} s at {} Gbit/s (bytes over the wire only)",
                e.gbit_seconds,
                e.gbit
            );
            say!(
                "estimate: data {:.1} s at the sampled read rate (a floor: a copy also writes), metadata about {:.1} s (four operations per entry at the scan rate); rough total {:.1} s with -parallel {}",
                e.projected_data_seconds,
                e.projected_metadata_seconds,
                e.projected_data_seconds + e.projected_metadata_seconds,
                opts.parallel
            );
            if scratch.is_some() {
                say!("live test copy: {} files, {} in {:.1} s = {}; whole tree at that rate about {:.1} s", e.live_files, human_bytes(e.live_bytes), e.live_seconds, rate(e.live_bytes, e.live_seconds), e.projected_live_seconds);
            }
            job.log("PASSED", &format!("{} bytes, {} files", e.bytes, e.files));
            pass()
        }
        Err(err) => {
            job.log("FAILED", &err.to_string());
            fail(format!("estimate: {err}"))
        }
    }
}

/// `rcp job start|list|status|wait|cancel|log|forget`: a run that outlives the call that
/// started it, for a caller that cannot hold a tool call open for a terabyte.
#[cfg(windows)]
fn run_job(_args: &Args, _root: &Path) -> ExitCode {
    fail("job: Windows detached jobs are unsupported until process-tree cancellation is qualified")
}

#[cfg(unix)]
fn run_job(args: &Args, root: &Path) -> ExitCode {
    let jobs = rcp::jobs::Jobs::at(root);
    let sub = args.sub.as_deref().unwrap_or("");
    let id = || -> Result<String, Failed> {
        args.positional.first().cloned().ok_or_else(|| {
            Failed::from(format!(
                "job {sub} needs a job id; `rcp job list` names them"
            ))
        })
    };
    let report = |j: &rcp::jobs::Job| {
        let mut e = Obj::new("job");
        for (k, v) in rcp::jobs::fields(j) {
            e = e.s(k, v);
        }
        e.emit();
        say!("{}", rcp::jobs::line(j));
    };
    match sub {
        "start" => {
            // the command to run is taken verbatim from this process's own arguments, not
            // from the parsed ones: the parser would otherwise eat the job's options as
            // though they were meant for `job` itself, and a copy would run without them
            let raw: Vec<String> = env::args().collect();
            let after = raw
                .iter()
                .position(|a| a == "start")
                .filter(|i| raw[..*i].iter().any(|a| a == "job"))
                .map(|i| i + 1);
            let command: Vec<String> = match after {
                Some(i) => raw[i..].to_vec(),
                None => Vec::new(),
            };
            if command.is_empty() {
                return fail("job start needs the command to run, as `rcp job start copy -newid ID SOURCE DESTINATION`");
            }
            if command.iter().any(|a| a == "-catalog") {
                return fail("-catalog goes before `job`, not inside the command it starts: the job and the reader have to agree where the catalog is");
            }
            let mut command = command;
            if let Err(e) = forward_job_rails(args, &mut command) {
                return fail(e);
            }
            let exe = match env::current_exe() {
                Ok(e) => e,
                Err(e) => return fail(io_failed("this program's own path", &e)),
            };
            match jobs.start(&exe, &command, root, VALUED) {
                Ok(j) => {
                    report(&j);
                    say!(
                        "job {} started; `rcp job status {}` says how it is going",
                        j.id,
                        j.id
                    );
                    pass()
                }
                Err(e) => fail(io_failed("job start", &e)),
            }
        }
        "list" => match jobs.list() {
            Ok(all) => {
                for j in &all {
                    let j = jobs.status(&j.id).unwrap_or_else(|_| j.clone());
                    report(&j);
                }
                say!(
                    "job list: {} job(s) under {}",
                    all.len(),
                    root.join("jobs").display()
                );
                pass()
            }
            Err(e) => fail(io_failed("job list", &e)),
        },
        "status" | "wait" | "cancel" | "forget" => {
            let id = match id() {
                Ok(i) => i,
                Err(e) => return fail(e),
            };
            let outcome = match sub {
                "status" => jobs.status(&id),
                "wait" => {
                    let limit = match args.value("t") {
                        None => std::time::Duration::from_secs(86_400),
                        Some(v) => match parse_duration(v) {
                            Ok(s) if s > 0.0 => std::time::Duration::from_secs_f64(s),
                            _ => return fail(format!("-t {v:?} is not a duration (use 30s, 5m)")),
                        },
                    };
                    jobs.wait(&id, std::time::Duration::from_millis(250), limit)
                }
                "cancel" => jobs.cancel(&id),
                _ => match jobs.forget(&id) {
                    Ok(()) => {
                        say!("job {id} forgotten");
                        return pass();
                    }
                    Err(e) => Err(e),
                },
            };
            match outcome {
                Ok(j) => {
                    report(&j);
                    if j.state == "failed" || j.state == "canceled" {
                        let text = jobs.messages_text(&j.id);
                        for l in text
                            .lines()
                            .filter(|l| l.starts_with("ERROR:") || l.starts_with("WARN:"))
                        {
                            say!("{l}");
                        }
                        if let Some(c) = &j.catalog {
                            // `resume` finishes a COPY: it walks what the catalog did not
                            // record and copies it. It never plans REMOVALS, so pointing a
                            // failed `sync` at it is advice that cannot work however often
                            // it is followed -- the same defect `Removed::or_refused` was
                            // built to fix in the foreground summary, still printed here
                            // because this arm read only the state and not the command.
                            match rcp::describe::verb_of(&j.argv, VALUED) {
                                Some(v) if rcp::describe::sweeps(v) => {
                                    say!("the catalog keeps what completed; run the same `{v}` again to finish it (`resume` does not plan removals, so it cannot)")
                                }
                                _ => say!("the catalog keeps what completed: `rcp resume -id {c}` finishes it"),
                            }
                        }
                    }
                    pass()
                }
                Err(e) => fail(io_failed(format!("job {sub}"), &e)),
            }
        }
        "log" => {
            let id = match id() {
                Ok(i) => i,
                Err(e) => return fail(e),
            };
            let from = args
                .value("n")
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0);
            match jobs.log(&id, from) {
                Ok((text, at)) => {
                    if json_on() {
                        sayp!("{text}");
                        out(format_args!("{text}"));
                        Obj::new("done")
                            .s("status", "passed")
                            .s("command", "job log")
                            .n("next", at)
                            .emit();
                        return ended(true);
                    }
                    sayp!("{text}");
                    say!(
                        "job log: {at} bytes read; `rcp job log -n {at} {id}` continues from here"
                    );
                    pass()
                }
                Err(e) => fail(io_failed("job log", &e)),
            }
        }
        other => fail(format!(
            "job {other:?}: use start, list, status, wait, cancel, log or forget"
        )),
    }
}

fn run_delete(args: &Args, root: &Path) -> ExitCode {
    let target = match one_endpoint(&args.positional, "delete") {
        Ok(e) => e,
        Err(e) => return fail(e),
    };
    if target.as_path() == Path::new("/") && target.is_local() {
        return fail("refusing to delete /");
    }
    let opts = DeleteOptions {
        parallel: match args.parallel() {
            Ok(p) => p,
            Err(e) => return fail(e),
        },
        filter: match args.filter() {
            Ok(f) => f,
            Err(e) => return fail(e),
        },
        force: args.has("force"),
        remove_top: args.has("removetopdir"),
        confirm: args.value("confirm").map(str::to_string),
        require_confirm: args.has("requireconfirm")
            || env::var("RCP_REQUIRE_CONFIRM").is_ok_and(|v| !v.is_empty()),
        runtime: Some(args.runtime.clone()),
    };
    let job = Job {
        root: root.to_path_buf(),
        command: "delete",
        id: "-".into(),
        source: target.display(),
        destination: String::new(),
        started: Instant::now(),
    };
    let tree = match open_tree(args, &target) {
        Ok(t) => t,
        Err(e) => return fail(e),
    };
    match transfer::delete_tree(&tree, &opts) {
        Ok(r) => {
            let mut summary = format!(
                "{} files ({} bytes), {} symlinks, {} directories",
                r.files, r.bytes, r.symlinks, r.directories
            );
            // Named in the summary rather than left to a debug line, because the count
            // beside it is what an operator reads as "the delete worked".
            if !r.deferred.is_empty() {
                summary.push_str(&format!(", {} deferred", r.deferred.len()));
            }
            if !r.kept.is_empty() {
                summary.push_str(&format!(", {} kept", r.kept.len()));
            }
            if r.dry_run {
                say!("delete (dry run, nothing removed): {summary}; add -force to delete");
                if !r.plan_digest.is_empty() {
                    say!("plan: {}", r.plan_digest);
                }
            } else {
                say!("delete: {summary}; {:.2} s", r.seconds);
            }
            for d in &r.deferred {
                Obj::new("deferred").s("path", d).emit();
                say!("DEFERRED: {d}");
            }
            for k in &r.kept {
                Obj::new("kept").s("path", k).emit();
                say!("KEPT: {k}");
            }
            for f in &r.failures {
                Obj::new("error")
                    .s("code", "io")
                    .s("op", "remove")
                    .s("message", f)
                    .emit();
                say!("ERROR: {f}");
            }
            // A refused entry is still there, so the delete did not do what it was asked;
            // the exit code says so and the KEPT lines say which. A deferred one is the
            // store's to finish and is not held against the run.
            let ok = r.failures.is_empty() && r.kept.is_empty();
            if !ok && r.failures.is_empty() {
                say!(
                    "ERROR: {} entries refused by the store are still there",
                    r.kept.len()
                );
            }
            Obj::new("done")
                .s("status", if ok { "passed" } else { "failed" })
                .s("command", "delete")
                .b("dry_run", r.dry_run)
                .n("files", r.files)
                .n("directories", r.directories)
                .n("symlinks", r.symlinks)
                .n("bytes", r.bytes)
                .n("deferred", r.deferred.len())
                .n("kept", r.kept.len())
                .n("failed", r.failures.len())
                .maybe(
                    "plan",
                    if r.plan_digest.is_empty() {
                        None
                    } else {
                        Some(&r.plan_digest)
                    },
                )
                .n("seconds", format!("{:.3}", r.seconds))
                .emit();
            if ok {
                job.log("PASSED", &summary);
                ended(true)
            } else {
                job.log("FAILED", &summary);
                ended(false)
            }
        }
        Err(e) => {
            job.log("FAILED", &e.to_string());
            fail(io_failed("delete", &e))
        }
    }
}

/// Owner or mode taken from `-reference PATH`.
fn reference_item(args: &Args, path: &str) -> Result<rcp::tree::Item, String> {
    let ep = Endpoint::parse(path).map_err(|e| format!("-reference: {e}"))?;
    let name = ep
        .path
        .file_name()
        .ok_or("-reference: not a path")?
        .to_string_lossy()
        .into_owned();
    // The whole path, not just the parent that gets opened: a symlink at the last
    // component would otherwise take the mode and owner from wherever it points. Same
    // shape as `diag -cat`, found in the same reading.
    allowed(args, &ep).map_err(|e| e.message)?;
    let tree = open_tree(args, &ep.parent())?;
    tree.stat(&name)
        .map_err(|e| format!("-reference {}: {e}", ep.display()))?
        .ok_or_else(|| format!("-reference {}: no such entry", ep.display()))
}

/// The worker side of `-nodes`: paths on stdin, a result line per path on stdout.
fn run_copybatch(args: &Args) -> ExitCode {
    let opts = match args.copy_options() {
        Ok(o) => o,
        Err(e) => return fail(e),
    };
    let (src, dst) = match endpoints(&args.positional, "copybatch") {
        Ok(v) => v,
        Err(e) => return fail(e),
    };
    let (stree, dtree) = match (open_tree(args, &src), open_destination(args, &dst)) {
        (Ok(s), Ok(d)) => (s, d),
        (Err(e), _) | (_, Err(e)) => return fail(e),
    };
    match cluster::serve_copybatch(&stree, &dtree, &opts.file_options(), opts.parallel) {
        Ok(_failures) => ExitCode::SUCCESS, // every failure is on its own line; the exit code says the worker ran
        Err(e) => fail(format!("copybatch: {e}")),
    }
}

/// The worker side of `scan -nodes`: subtree paths on stdin, one listing line per entry.
fn run_scanbatch(args: &Args) -> ExitCode {
    let src = match one_endpoint(&args.positional, "scanbatch") {
        Ok(e) => e,
        Err(e) => return fail(e),
    };
    let opts = ScanOptions {
        runtime: args.runtime.clone(),
        parallel: match args.parallel() {
            Ok(p) => p,
            Err(e) => return fail(e),
        },
        filter: match args.filter() {
            Ok(f) => f,
            Err(e) => return fail(e),
        },
        max_depth: None,
        hash: args.has("sha256")
            || args.has("md5")
            || args.has("blake3")
            || args.has("xxh3")
            || args.has("xxh128"),
        dedupe: false,
        block_size: match args.block_size() {
            Ok(b) => b,
            Err(e) => return fail(e),
        },
        names: false,
        // The batch worker hashes one subtree per invocation, on a node whose catalog root
        // is not this tree's. See the `-hashcache` arming in `run_scan`.
        cache: None,
    };
    let mut input = Vec::new();
    if let Err(e) = io::Read::read_to_end(&mut io::stdin().lock(), &mut input) {
        return fail(format!("scanbatch: stdin: {e}"));
    }
    let out = io::stdout();
    for rel in input
        .split(|b| *b == 0)
        .filter(|r| !r.is_empty())
        .map(|r| String::from_utf8_lossy(r).to_string())
    {
        let sub = src.join(&rel);
        let result = open_tree(args, &sub)
            .map_err(io::Error::other)
            .and_then(|t| scan::scan(&t, &opts));
        match result {
            Ok(s) => {
                let mut o = out.lock();
                for i in &s.listing.items {
                    if i.rel == "." {
                        continue;
                    }
                    let mut full = i.clone();
                    full.rel = format!("{rel}/{}", i.rel);
                    let _ = io::Write::write_all(
                        &mut o,
                        format!(
                            "{}\n",
                            cluster::item_line(&full, s.hashes.get(&i.rel).map(String::as_str))
                        )
                        .as_bytes(),
                    );
                }
                for e in &s.listing.errors {
                    let _ = io::Write::write_all(&mut o, format!("error\t{rel}: {e}\n").as_bytes());
                }
            }
            Err(e) => say!("error\t{rel}: {e}"),
        }
    }
    ExitCode::SUCCESS
}

#[cfg(windows)]
fn run_diag(_args: &Args, _root: &Path) -> ExitCode {
    fail("diag: these utilities have not been ported to Windows")
}

#[cfg(unix)]
fn run_diag(args: &Args, root: &Path) -> ExitCode {
    use rcp::diag;
    let parallel = match args.parallel() {
        Ok(p) => p,
        Err(e) => return fail(e),
    };
    match args.sub.as_deref() {
        None => {
            // simple file utilities and -rmid
            if let Some(id) = args.value("rmid") {
                return match Catalog::delete(root, id) {
                    Ok(()) => {
                        say!("diag: removed index {id}");
                        pass()
                    }
                    Err(e) => fail(format!("-rmid {id}: {e}")),
                };
            }
            let ops: Vec<(&str, &str)> = ["cat", "mkdir", "rmdir", "rmrf"]
                .iter()
                .filter_map(|k| args.value(k).map(|v| (*k, v)))
                .collect();
            let (op, path) = match ops.as_slice() {
                [one] => *one,
                [] => return fail("diag needs one of -cat, -mkdir, -rmdir, -rmrf PATH or -rmid ID, or a subcommand: nio, find, change, indexdiag, rebuild, dump"),
                _ => return fail("diag takes one file utility at a time"),
            };
            let ep = match Endpoint::parse(path) {
                Ok(e) => e,
                Err(e) => return fail(e.to_string()),
            };
            if op == "rmrf" {
                let tree = match open_tree(args, &ep) {
                    Ok(t) => t,
                    Err(e) => return fail(e),
                };
                let opts = DeleteOptions {
                    parallel,
                    filter: Filter::default(),
                    force: true,
                    remove_top: true,
                    confirm: None,
                    require_confirm: false,
                    runtime: None,
                };
                return match transfer::delete_tree(&tree, &opts) {
                    Ok(r) => {
                        let mut tail = String::new();
                        if !r.deferred.is_empty() {
                            tail.push_str(&format!(", {} deferred", r.deferred.len()));
                        }
                        if !r.kept.is_empty() {
                            tail.push_str(&format!(", {} kept", r.kept.len()));
                        }
                        say!(
                            "diag -rmrf {}: {} files, {} symlinks, {} directories removed{tail}",
                            ep.display(),
                            r.files,
                            r.symlinks,
                            r.directories
                        );
                        for d in &r.deferred {
                            Obj::new("deferred").s("path", d).emit();
                            say!("DEFERRED: {d}");
                        }
                        // events as well as lines: `-rmrf -json` printed the lines and no
                        // events, so a caller reading the stream saw a clean removal
                        for k in &r.kept {
                            Obj::new("kept").s("path", k).emit();
                            say!("KEPT: {k}");
                        }
                        for f in &r.failures {
                            say!("ERROR: {f}");
                        }
                        if r.failures.is_empty() && r.kept.is_empty() {
                            pass()
                        } else if r.failures.is_empty() {
                            fail(format!(
                                "-rmrf {}: {} entries refused by the store are still there",
                                ep.display(),
                                r.kept.len()
                            ))
                        } else {
                            fail(format!(
                                "-rmrf {}: {} failures",
                                ep.display(),
                                r.failures.len()
                            ))
                        }
                    }
                    Err(e) => fail(format!("-rmrf {}: {e}", ep.display())),
                };
            }
            let name = match ep.path.file_name() {
                Some(n) if ep.path != Path::new("/") => n.to_string_lossy().into_owned(),
                _ => {
                    return fail(format!(
                        "-{op} {path}: names the root of its endpoint; give a path inside it"
                    ))
                }
            };
            // The WHOLE path goes through the rails, and not only the parent that gets
            // opened. Checking only the parent is not enough: a symlink at the last
            // component moves the read somewhere the rail never saw. Measured -- with only
            // the parent checked, `diag -cat /allowed/link -allow /allowed` printed
            // /etc/hostname.
            // `allowed` resolves the path the way the kernel does, final component
            // included, so it catches the link; the parent is still what gets opened,
            // because that is how the tree is addressed.
            if let Err(e) = allowed(args, &ep) {
                return fail(e);
            }
            let parent = match open_tree(args, &ep.parent()) {
                Ok(t) => t,
                Err(e) => return fail(e),
            };
            let result = match op {
                "cat" => diag::cat(&parent, &name, &mut io::stdout().lock())
                    .inspect_err(rcp::exit_if_reader_left)
                    .map(|n| format!("diag -cat {}: {n} bytes", ep.display())),
                "mkdir" => parent
                    .mkdir(&name)
                    .map(|_| format!("diag -mkdir {}: created", ep.display())),
                // `|_|` here threw the third answer away: a namenode declining to delete
                // a non-empty directory, or a locked WebDAV collection, printed "removed"
                "rmdir" => parent.remove(&name, Kind::Dir).and_then(|r| match r {
                    rcp::tree::Removed::Gone => {
                        Ok(format!("diag -rmdir {}: removed", ep.display()))
                    }
                    rcp::tree::Removed::Deferred(why) => {
                        Ok(format!("diag -rmdir {}: deferred, {why}", ep.display()))
                    }
                    rcp::tree::Removed::Kept(why) => {
                        Err(io::Error::other(format!("not removed: {why}")))
                    }
                }),
                _ => unreachable!(),
            };
            match result {
                Ok(line) => {
                    if op != "cat" || !args.has("q") {
                        eprintln!("{line}");
                    }
                    if op == "cat" {
                        ExitCode::SUCCESS // the bytes are the output; no STATUS line to keep them clean
                    } else {
                        pass()
                    }
                }
                Err(e) => fail(format!("-{op} {}: {e}", ep.display())),
            }
        }
        Some("dump") => {
            let procs = diag::processes();
            let which: Option<usize> = args.value("n").map(|v| v.parse().unwrap_or(0));
            let shown: Vec<_> = procs
                .iter()
                .enumerate()
                .filter(|(i, _)| which.is_none_or(|n| *i == n))
                .collect();
            say!(
                "{:<8} {:>10} {:>8} {:>5} command",
                "pid",
                "rss",
                "threads",
                "fds"
            );
            for (_, p) in &shown {
                say!(
                    "{:<8} {:>10} {:>8} {:>5} {}",
                    p.pid,
                    human_bytes(p.rss_kib * 1024),
                    p.threads,
                    p.fds,
                    p.command
                );
            }
            say!(
                "diag dump: {} rcp process(es){}",
                shown.len(),
                if procs.is_empty() {
                    " (none running besides this one)"
                } else {
                    ""
                }
            );
            pass()
        }
        Some("nio") => {
            let ep = match one_endpoint(&args.positional, "diag nio") {
                Ok(e) => e,
                Err(e) => return fail(e),
            };
            let pct = |k: &str| -> Result<Option<u32>, String> {
                args.value(k)
                    .map(|v| {
                        v.trim_end_matches('%')
                            .parse::<u32>()
                            .ok()
                            .filter(|p| *p <= 100)
                            .ok_or_else(|| format!("-{k} {v:?}: a percentage from 0 to 100"))
                    })
                    .transpose()
            };
            let read_pct = match (args.has("read"), args.has("write"), pct("read%")) {
                (_, _, Err(e)) => return fail(e),
                (true, false, _) => 100,
                (false, true, _) => 0,
                (_, _, Ok(Some(p))) => p,
                _ => 50,
            };
            let random_pct = match (args.has("random"), args.has("sequential"), pct("rand%")) {
                (_, _, Err(e)) => return fail(e),
                (true, false, _) => 100,
                (false, true, _) => 0,
                (_, _, Ok(Some(p))) => p,
                _ => 50,
            };
            let seconds = match args.value("t").map(parse_duration).transpose() {
                Ok(s) => s.unwrap_or(60.0),
                Err(e) => return fail(format!("-t {e}")),
            };
            let file_size = match args.value("size").map(parse_size).transpose() {
                Ok(s) => s.unwrap_or(64 << 20),
                Err(e) => return fail(format!("-size {e}")),
            };
            let pending: usize = match args.value("npend").map(|v| v.parse::<usize>()).transpose() {
                Ok(p) => p.unwrap_or(16).clamp(1, 64),
                Err(_) => return fail("-npend needs a number"),
            };
            let opts = diag::NioOptions {
                seconds,
                read_pct,
                random_pct,
                block_size: match args.block_size() {
                    Ok(b) => b,
                    Err(e) => return fail(e),
                },
                parallel,
                pending,
                file_size,
                random_data: args.has("wrdata"),
            };
            let tree = match open_destination(args, &ep) {
                Ok(t) => t,
                Err(e) => return fail(e),
            };
            let local_root = if ep.is_local() {
                Some(ep.path.clone())
            } else {
                None
            };
            match diag::nio(&tree, local_root.as_deref(), &opts) {
                Ok(r) => {
                    say!("{}", r.render());
                    for w in &r.warnings {
                        say!("WARN: {w}");
                    }
                    for f in &r.failures {
                        say!("ERROR: {f}");
                    }
                    if r.failures.is_empty() {
                        pass()
                    } else {
                        say!("STATUS: FAILED");
                        ExitCode::from(1)
                    }
                }
                Err(e) => fail(format!("diag nio {}: {e}", ep.display())),
            }
        }
        Some("find") => {
            let ep = match one_endpoint(&args.positional, "diag find") {
                Ok(e) => e,
                Err(e) => return fail(e),
            };
            let (mode, pattern) = match (args.value("branch-match"), args.value("top-match")) {
                (Some(p), None) => (diag::FindMode::Branch, p),
                (None, Some(p)) => (diag::FindMode::Top, p),
                _ => {
                    return fail(
                        "diag find needs exactly one of -branch-match GLOB or -top-match GLOB",
                    )
                }
            };
            let filter = match args.filter() {
                Ok(f) => f,
                Err(e) => return fail(e),
            };
            let tree = match open_tree(args, &ep) {
                Ok(t) => t,
                Err(e) => return fail(e),
            };
            match diag::find(&tree, mode, pattern, &filter, parallel) {
                Ok(r) => {
                    if !args.has("q") {
                        if let Some(t) = args.value("fmt") {
                            sayp!(
                                "{}",
                                scan::format_report(
                                    &diag::as_scan(
                                        r.branches.iter().map(|(i, _, _)| i.clone()).collect(),
                                        &args.runtime
                                    ),
                                    t
                                )
                            );
                        } else if args.has("l") {
                            for (i, m, n) in &r.branches {
                                say!(
                                    "{}  {m} of {n} files match",
                                    scan::long_line(
                                        i,
                                        if args.has("nonames") {
                                            None
                                        } else {
                                            Some(&*args.runtime.names)
                                        },
                                        None
                                    )
                                );
                            }
                        } else {
                            for (i, m, n) in &r.branches {
                                say!("{}  ({m} of {n} files match)", i.rel);
                            }
                        }
                    }
                    for e in &r.errors {
                        say!("WARN: {e}");
                    }
                    say!(
                        "diag find: {} {} under {}",
                        r.branches.len(),
                        if mode == diag::FindMode::Top {
                            "top-level branches whose files all match"
                        } else {
                            "directories with a matching file"
                        },
                        ep.display()
                    );
                    pass()
                }
                Err(e) => fail(format!("diag find {}: {e}", ep.display())),
            }
        }
        Some("change") => {
            let ep = match one_endpoint(&args.positional, "diag change") {
                Ok(e) => e,
                Err(e) => return fail(e),
            };
            let resolve_u = |v: &str| names::uid_of(v);
            let resolve_g = |v: &str| names::gid_of(v);
            let read_map = |k: &str,
                            resolve: &dyn Fn(&str) -> Option<u32>|
             -> Result<Option<BTreeMap<u32, u32>>, String> {
                match args.value(k) {
                    None => Ok(None),
                    Some(p) => {
                        // A file, and not one to open with a bare `read_to_string`: with no
                        // rail in the way, and a parse error that echoes the offending LINE
                        // back, `-umap /etc/shadow` under `-allow` printed a password hash.
                        // Measured. It goes through the same check as any endpoint, and the
                        // error names the line number and what was expected rather than
                        // what it read.
                        let ep = Endpoint::parse(p).map_err(|e| format!("-{k}: {e}"))?;
                        allowed(args, &ep).map_err(|e| e.message)?;
                        let text = fs::read_to_string(p).map_err(|e| format!("-{k} {p}: {e}"))?;
                        diag::parse_map(&text, resolve)
                            .map(Some)
                            .map_err(|e| format!("-{k} {p}: {e}"))
                    }
                }
            };
            let change = if args.value("u").is_some() || args.value("g").is_some() {
                let uid = match args
                    .value("u")
                    .map(|v| {
                        resolve_u(v)
                            .ok_or_else(|| format!("-u {v:?}: not a number or a known user"))
                    })
                    .transpose()
                {
                    Ok(u) => u,
                    Err(e) => return fail(e),
                };
                let gid = match args
                    .value("g")
                    .map(|v| {
                        resolve_g(v)
                            .ok_or_else(|| format!("-g {v:?}: not a number or a known group"))
                    })
                    .transpose()
                {
                    Ok(g) => g,
                    Err(e) => return fail(e),
                };
                Change::Owner {
                    uid,
                    gid,
                    from_uid: None,
                    from_gid: None,
                }
            } else if args.value("umap").is_some() || args.value("gmap").is_some() {
                let uid_map = match read_map("umap", &resolve_u) {
                    Ok(m) => m.unwrap_or_default(),
                    Err(e) => return fail(e),
                };
                let gid_map = match read_map("gmap", &resolve_g) {
                    Ok(m) => m.unwrap_or_default(),
                    Err(e) => return fail(e),
                };
                Change::OwnerMap { uid_map, gid_map }
            } else if args.value("atime").is_some() || args.value("mtime").is_some() {
                let parse = |k: &str| {
                    args.value(k)
                        .map(|v| diag::parse_timestamp(v).map_err(|e| format!("-{k} {e}")))
                        .transpose()
                };
                match (parse("atime"), parse("mtime")) {
                    (Ok(atime_ns), Ok(mtime_ns)) => Change::Times { atime_ns, mtime_ns },
                    (Err(e), _) | (_, Err(e)) => return fail(e),
                }
            } else {
                return fail("diag change needs -u/-g, -umap/-gmap, or -atime/-mtime");
            };
            let filter = match args.filter() {
                Ok(f) => f,
                Err(e) => return fail(e),
            };
            let tree = match open_tree(args, &ep) {
                Ok(t) => t,
                Err(e) => return fail(e),
            };
            let depth = match args.value("depth").map(|v| v.parse::<usize>()).transpose() {
                Ok(d) => d,
                Err(_) => return fail("-depth needs a number"),
            };
            match transfer::apply_tree_depth(&tree, &filter, depth, parallel, change, args.has("v"))
            {
                Ok(r) => {
                    for p in &r.changed_paths {
                        say!("changed {p}");
                    }
                    for f in &r.failures {
                        say!("ERROR: {f}");
                    }
                    say!(
                        "diag change: {} entries changed, {} failed; {:.2} s",
                        r.changed,
                        r.failures.len(),
                        r.seconds
                    );
                    if r.failures.is_empty() {
                        pass()
                    } else {
                        say!("STATUS: FAILED");
                        ExitCode::from(1)
                    }
                }
                Err(e) => fail(format!("diag change {}: {e}", ep.display())),
            }
        }
        Some(which @ ("indexdiag" | "rebuild")) => {
            let Some(id) = args.value("id") else {
                return fail(format!("diag {which} needs -id ID"));
            };
            let cat = match Catalog::open(root, id) {
                Ok(c) => c,
                Err(e) => return fail(format!("-id {id}: {e}")),
            };
            let dest_ep = match endpoint_of(&cat.destination) {
                Ok(e) => e,
                Err(e) => return fail(e),
            };
            let dest = match open_tree(args, &dest_ep) {
                Ok(t) => t,
                Err(e) => return fail(e),
            };
            let do_rebuild = which == "rebuild" || args.has("rebuild");
            let replace = which == "rebuild" || args.has("replace");
            if !do_rebuild {
                let entries = match cat.entries() {
                    Ok(e) => e,
                    Err(e) => return fail(format!("-id {id}: {e}")),
                };
                let listing = match dest.list(&Filter::default(), None, parallel) {
                    Ok(l) => l,
                    Err(e) => return fail(format!("{}: {e}", dest_ep.display())),
                };
                let r = diag::diagnose(&entries, &listing.items);
                for p in &r.orphans {
                    say!("orphan {p}: parent directory not in the index");
                }
                for p in &r.missing {
                    say!("missing {p}: not on the destination");
                }
                for p in &r.unlisted {
                    say!("unlisted {p}: on the destination, not in the index");
                }
                let problems = r.orphans.len() + r.missing.len() + r.unlisted.len();
                say!(
                    "diag indexdiag {id}: {} entries, {} orphans, {} missing, {} unlisted{}",
                    r.entries,
                    r.orphans.len(),
                    r.missing.len(),
                    r.unlisted.len(),
                    if problems > 0 {
                        "; -rebuild rebuilds the index from the destination"
                    } else {
                        ""
                    }
                );
                return if problems == 0 {
                    pass()
                } else {
                    say!("ERROR: index {id} has {problems} problem(s)");
                    say!("STATUS: FAILED");
                    ExitCode::from(1)
                };
            }
            let (source_text, destination_text) = (
                cat.source.to_string_lossy().into_owned(),
                cat.destination.to_string_lossy().into_owned(),
            );
            drop(cat);
            match diag::rebuild(
                root,
                id,
                &dest,
                &source_text,
                &destination_text,
                parallel,
                replace,
                &args.runtime,
            ) {
                Ok((new_id, n)) => {
                    say!(
                        "diag {which}: index {new_id} rebuilt from {} with {n} entries{}",
                        dest_ep.display(),
                        if replace {
                            " (replaced the original)"
                        } else {
                            ""
                        }
                    );
                    pass()
                }
                Err(e) => fail(format!("diag {which} {id}: {e}")),
            }
        }
        Some(other) => fail(format!("diag {other}: unknown subcommand")),
    }
}

fn run_apply(args: &Args, root: &Path) -> ExitCode {
    let is_chown = args.command == "chown";
    let flag_form = [
        "user",
        "group",
        "user-from",
        "group-from",
        "reference",
        "mode",
    ]
    .iter()
    .any(|k| args.value(k).is_some());
    let (spec, target) = match (args.positional.as_slice(), flag_form) {
        ([path], true) => (None, path),
        ([spec, path], false) => (Some(spec.as_str()), path),
        _ => {
            return fail(format!(
                "{} needs {} and PATH",
                args.command,
                if is_chown {
                    "-user, -group, -reference, or UID[:GID]"
                } else {
                    "-mode, -reference, or MODE"
                }
            ))
        }
    };
    let reference = match args.value("reference") {
        Some(p) => match reference_item(args, p) {
            Ok(i) => Some(i),
            Err(e) => return fail(e),
        },
        None => None,
    };
    let change = if is_chown {
        let (mut uid, mut gid) = (None, None);
        if let Some(spec) = spec {
            let (u, g) = spec
                .split_once(':')
                .map(|(u, g)| (u, Some(g)))
                .unwrap_or((spec, None));
            if !u.is_empty() {
                uid = Some(match names::uid_of(u) {
                    Some(n) => n,
                    None => return fail(format!("chown {u:?}: not a number or a known user")),
                });
            }
            if let Some(g) = g.filter(|g| !g.is_empty()) {
                gid = Some(match names::gid_of(g) {
                    Some(n) => n,
                    None => return fail(format!("chown {g:?}: not a number or a known group")),
                });
            }
        }
        if let Some(u) = args.value("user") {
            uid = Some(match names::uid_of(u) {
                Some(n) => n,
                None => return fail(format!("-user {u:?}: not a number or a known user")),
            });
        }
        if let Some(g) = args.value("group") {
            gid = Some(match names::gid_of(g) {
                Some(n) => n,
                None => return fail(format!("-group {g:?}: not a number or a known group")),
            });
        }
        if let Some(r) = &reference {
            uid = Some(r.uid);
            gid = Some(r.gid);
        }
        let from_uid = match args.value("user-from") {
            Some(u) => match names::uid_of(u) {
                Some(n) => Some(n),
                None => return fail(format!("-user-from {u:?}: not a number or a known user")),
            },
            None => None,
        };
        let from_gid = match args.value("group-from") {
            Some(g) => match names::gid_of(g) {
                Some(n) => Some(n),
                None => return fail(format!("-group-from {g:?}: not a number or a known group")),
            },
            None => None,
        };
        if uid.is_none() && gid.is_none() {
            return fail("chown needs -user, -group, -reference, or UID[:GID]");
        }
        Change::Owner {
            uid,
            gid,
            from_uid,
            from_gid,
        }
    } else {
        let mode = match (spec, args.value("mode"), &reference) {
            (_, _, Some(r)) => r.mode,
            (_, Some(m), _) | (Some(m), _, _) => match u32::from_str_radix(m, 8) {
                Ok(m) if m <= 0o7777 => m,
                _ => return fail(format!("chmod {m:?}: use an octal mode such as 0644")),
            },
            _ => return fail("chmod needs -mode, -reference, or MODE"),
        };
        Change::Mode(mode)
    };
    let ep = match Endpoint::parse(target) {
        Ok(e) => e,
        Err(e) => return fail(e.to_string()),
    };
    let parallel = match args.parallel() {
        Ok(p) => p,
        Err(e) => return fail(e),
    };
    let filter = match args.filter() {
        Ok(f) => f,
        Err(e) => return fail(e),
    };
    let job = Job {
        root: root.to_path_buf(),
        command: &args.command,
        id: "-".into(),
        source: ep.display(),
        destination: String::new(),
        started: Instant::now(),
    };
    let tree = match open_tree(args, &ep) {
        Ok(t) => t,
        Err(e) => return fail(e),
    };
    // A destination that keeps no metadata would walk the whole tree, accept every change
    // and report the count, having stored none of it. That is the silent success this
    // codebase refuses elsewhere; say so instead, before anything is walked.
    if !tree.rewrites_metadata_in_place() {
        return fail(format!("{}: {} cannot change modes, owners or times once written, so there is nothing for {} to change", args.command, ep.display(), args.command));
    }
    match transfer::apply_tree(&tree, &filter, parallel, change, args.has("v")) {
        Ok(r) => {
            for p in &r.changed_paths {
                say!("changed {p}");
            }
            say!(
                "{}: {} entries changed; {:.2} s",
                args.command,
                r.changed,
                r.seconds
            );
            for f in &r.failures {
                say!("ERROR: {f}");
            }
            if r.failures.is_empty() {
                job.log("PASSED", &format!("{} changed", r.changed));
                pass()
            } else {
                job.log(
                    "FAILED",
                    &format!("{} changed, {} failed", r.changed, r.failures.len()),
                );
                say!("STATUS: FAILED");
                ExitCode::from(1)
            }
        }
        Err(e) => {
            job.log("FAILED", &e.to_string());
            fail(io_failed(&args.command, &e))
        }
    }
}

/// `File::create`, except that a symlink sitting at `path` is an error rather than a
/// redirection. `O_NOFOLLOW` is the same flag the uring engine opens destinations with,
/// for the same reason: a name this run chose is not a file this run made.
#[cfg(windows)]
fn create_nofollow(path: &Path) -> io::Result<fs::File> {
    rcp::windows::PrivateOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
}

#[cfg(unix)]
fn create_nofollow(path: &Path) -> io::Result<fs::File> {
    use rcp::platform::O_NOFOLLOW;
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)
}

fn run_logdump(args: &Args, root: &Path) -> ExitCode {
    let id = logdump_id(args);
    let lines = match JobLog::read(root, id.as_deref()) {
        Ok(l) => l,
        Err(e) => return fail(format!("logdump: {e}")),
    };
    say!("time\tcommand\tid\tsource\tdestination\tstatus\tseconds\tsummary");
    for l in &lines {
        say!("{l}");
    }
    say!(
        "logdump: {} jobs from {}",
        lines.len(),
        root.join("jobs.log").display()
    );
    if let Some(id) = id {
        // logdump writes <ID>.zip in the working directory: the job lines and,
        // when the ID has a catalog, its index.
        if !Catalog::valid_id(&id) {
            return fail(format!("logdump: {id:?} is not a valid ID"));
        }
        let name = format!("{id}.zip");
        // The zip lands in the WORKING DIRECTORY, which is a path this run never named and
        // which `-allow` therefore has to be asked about explicitly -- it is checked here
        // rather than at the top because it is not an endpoint of the command. Measured
        // before this: `-allow /safe logdump demo` from outside /safe wrote the zip.
        let full = match env::current_dir() {
            Ok(d) => d.join(&name),
            Err(e) => return fail(io_failed("this run's working directory", &e)),
        };
        match Endpoint::parse(&full.to_string_lossy()) {
            Ok(ep) => {
                if let Err(e) = allowed(args, &ep) {
                    return fail(e);
                }
            }
            Err(e) => return fail(e.to_string()),
        }
        let mut jobs = lines.join("\n");
        jobs.push('\n');
        // `O_NOFOLLOW`, because the name is chosen by the ID and the file may already be a
        // symlink someone else put there: `File::create` followed it and wrote zip bytes
        // through to its target. The kernel refusing is better than a stat first, which
        // would leave the window between the two open.
        let result = create_nofollow(&full).and_then(|f| {
            let mut z = ZipWriter::new(f);
            z.add(&format!("{id}/jobs.log"), jobs.as_bytes())?;
            // through the catalog, which refuses a link in place of the index; a bare
            // `fs::read` here followed one, and zipped whatever it pointed at
            match Catalog::index_bytes(root, &id) {
                Ok(index) => z.add(&format!("{id}/index.tsv"), &index)?,
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
            z.finish().map(|_| ())
        });
        match result {
            Ok(()) => say!("wrote {name}"),
            // ELOOP here is the `O_NOFOLLOW` refusal, and the kernel's wording for it --
            // "too many levels of symbolic links" -- describes a different problem than
            // the one the operator has, which is that something is already sitting there
            Err(e) if e.raw_os_error() == Some(40) => {
                return fail(format!(
                    "logdump: {name} is a symlink; it would be written through to its target"
                ))
            }
            Err(e) => return fail(format!("logdump: {name}: {e}")),
        }
    }
    pass()
}

fn main() -> ExitCode {
    // SIGPIPE stays ignored; a closed stdout is handled in `out`, where it belongs.
    let mut args = match parse_args(env::args().skip(1).collect()) {
        Ok(a) => a,
        Err(e) => {
            say!("{USAGE}");
            return fail(e);
        }
    };
    if args.has("json") {
        JSON.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    #[cfg(windows)]
    if args.has("nocache") {
        return fail("-nocache: Windows page-cache eviction is unsupported");
    }
    #[cfg(windows)]
    if matches!(
        args.command.as_str(),
        "chmod" | "chown" | "show" | "copybatch" | "scanbatch"
    ) {
        return fail(format!(
            "{}: this operation is unsupported on Windows",
            args.command
        ));
    }
    let root = catalog_dir(args.value("catalog"));
    // the driving adapter assembles the ports: nothing here is process-wide
    let log: Arc<dyn Log> = match args.value("loglevel").map(|v| v.to_ascii_uppercase()) {
        None => Arc::new(rcp::ports::Silent),
        Some(l) if l == "INFO" => Arc::new(rcp::ports::Silent),
        Some(l) if l == "DEBUG" => Arc::new(rcp::log::Stderr),
        Some(l) => return fail(format!("-loglevel {l:?}: use INFO or DEBUG")),
    };
    let throttle: Arc<dyn rcp::ports::Throttle> = match args.value("bwlimit") {
        None => Arc::new(rcp::ports::Unlimited),
        Some(v) => match parse_size(v.trim_end_matches("/s")) {
            Ok(n) if n >= 4096 => Arc::new(rcp::throttle::TokenBucket::new(n)),
            Ok(_) => return fail("-bwlimit must be at least 4k per second"),
            Err(e) => return fail(format!("-bwlimit {e}")),
        },
    };
    // One name wins, and the order is the strongest first, so a command line that asks
    // for two gets the safer answer rather than whichever was checked last.
    let algorithm = if args.has("blake3") {
        rcp::hash::Algorithm::Blake3
    } else if args.has("xxh128") {
        rcp::hash::Algorithm::Xxh128
    } else if args.has("xxh3") {
        rcp::hash::Algorithm::Xxh3
    } else {
        rcp::hash::Algorithm::Sha256
    };
    let digests = algorithm.digests();
    args.runtime = Runtime {
        digests,
        chunk_digests: rcp::hash::Algorithm::Sha256.digests(),
        throttle,
        log: log.clone(),
        names: Arc::new(names::SystemNames),
    };
    let mut transports = Transports::from_env(log.clone());
    // Field by field, not all-or-nothing. It used to be `if any s3.* option is present,
    // replace the whole thing`, so `-s3.insecure` on the command line ALSO discarded the
    // `RCP_S3_ENDPOINT` and `RCP_S3_PROFILE` the environment had set -- which under an MCP
    // server is the operator's configuration being erased by a caller's switch. A switch
    // can only be written true on a command line, so an absent one keeps whatever the
    // environment said rather than meaning "off".
    #[cfg(feature = "s3")]
    {
        let cli = args.s3_options();
        transports.s3 = S3Options {
            endpoint: cli.endpoint.or(transports.s3.endpoint),
            profile: cli.profile.or(transports.s3.profile),
            insecure: cli.insecure || transports.s3.insecure,
            noverify: cli.noverify || transports.s3.noverify,
        };
    }
    // `-s3.noverify` (or `RCP_S3_NOVERIFY`) turns verification off for hdfs and oci too, so
    // a build without S3 still reads it.
    #[cfg(all(feature = "s3", any(feature = "hdfs", feature = "oci")))]
    let noverify = transports.s3.noverify;
    #[cfg(all(not(feature = "s3"), any(feature = "hdfs", feature = "oci")))]
    let noverify =
        args.has("s3.noverify") || env::var("RCP_S3_NOVERIFY").is_ok_and(|v| !v.is_empty());
    #[cfg(all(feature = "hdfs", unix))]
    {
        transports.hdfs.noverify = noverify;
    }
    // One policy, both adapters. It was set only on `oci` while `hdfs` followed any
    // namenode redirect it was given, which is the whole reason the rule now lives in
    // `ports` rather than inside the registry client.
    let away = match away_policy(&args) {
        Ok(a) => a,
        Err(e) => return fail(e),
    };
    #[cfg(feature = "oci")]
    {
        transports.oci.away = away.clone();
    }
    #[cfg(all(feature = "hdfs", unix))]
    {
        transports.hdfs.away = away;
    }
    // still worked out without either, so a malformed `-allow` is refused in every build
    #[cfg(not(all(feature = "hdfs", unix)))]
    let _ = away;
    if let Some(v) = args.value("via") {
        // `ssh://hop` with no path is the natural spelling and the parser wants one. The
        // scheme has to come off before the `/` test or `rcps://h:1` reads as having a path.
        let bare = ["ssh://", "rcps://", "rcp://"]
            .iter()
            .find_map(|s| v.strip_prefix(s))
            .unwrap_or(v);
        let text = if bare.contains('/') {
            v.to_string()
        } else {
            format!("{v}/")
        };
        match Endpoint::parse(&text) {
            Ok(ep) if ep.is_serve() => transports.via = Some(ep),
            Ok(_) => {
                return fail(format!(
                    "-via {v}: a relay is an ssh://[user@]host[:port] or an rcp://host:port"
                ))
            }
            Err(e) => return fail(format!("-via {v}: {e}")),
        }
    }
    #[cfg(feature = "dav")]
    {
        transports.dav.insecure |=
            args.has("dav.insecure") || env::var("RCP_DAV_INSECURE").is_ok_and(|v| !v.is_empty());
        transports.dav.noverify |= args.has("dav.noverify");
        if let Some(u) = args.value("dav.user") {
            transports.dav.user = Some(u.to_string());
        }
    }
    #[cfg(feature = "https")]
    {
        transports.https.noverify |= args.has("http.noverify");
        if let Some(u) = args.value("http.user") {
            transports.https.user = Some(u.to_string());
        }
        if let Some(n) = args.value("http.index") {
            transports.https.index = Some(n.to_string());
        }
    }
    #[cfg(feature = "smb")]
    {
        if let Some(u) = args.value("smb.user") {
            transports.smb.user = Some(u.to_string());
        }
        transports.smb.require_signing |= args.has("smb.sign");
        if let Some(v) = args.value("smb.handshake") {
            match v.trim().parse::<u64>() {
                // The deadline the handshake runs on. Refusing a non-number here rather than
                // falling back is the right side to be strict on: a typo that silently kept the
                // 10 s default would look exactly like the flag not working.
                Ok(n) if n > 0 => transports.smb.handshake_secs = Some(n),
                _ => {
                    return fail(format!(
                        "-smb.handshake takes a positive whole number of seconds, not {v:?}"
                    ))
                }
            }
        }
    }
    #[cfg(feature = "oci")]
    {
        transports.oci.insecure |= args.has("oci.insecure");
        transports.oci.noverify |= args.has("oci.noverify") || noverify;
        if let Some(u) = args.value("oci.user") {
            if !u.contains(':') {
                return fail("-oci.user takes USER:PASSWORD");
            }
            transports.oci.user = Some(u.to_string());
        }
    }
    #[cfg(all(feature = "hdfs", unix))]
    if let Some(nn) = args.value("hdfs.namenode") {
        transports.hdfs.namenode = Some(nn.to_string());
    }
    #[cfg(all(feature = "remote", unix))]
    {
        if let Some(r) = args.value("rcp.remote") {
            transports.ssh.remote_rcp = r.to_string();
        }
        transports.ssh.compress = args.has("compress");
        // `-compress-codec` is an accepted alternate spelling, kept for compatibility; it is the
        // same option, and naming two different codecs is a contradiction rather than a
        // precedence question.
        let codec_name = match (args.value("compress.codec"), args.value("compress-codec")) {
            (Some(a), Some(b)) if a != b => {
                return fail(format!(
                    "-compress.codec {a} and -compress-codec {b} name two codecs; give one"
                ))
            }
            (a, b) => a.or(b),
        };
        if let Some(name) = codec_name {
            let Some(c) = rcp::remote::proto::Codec::by_name(name) else {
                return fail(format!("-compress.codec {name}: lz4, deflate or zstd"));
            };
            transports.ssh.codec = c;
            // Naming a codec is asking to compress. Requiring `-compress` as well would be a
            // second way to say the same thing, and the failure mode of forgetting it is a run
            // that silently sends everything raw.
            transports.ssh.compress = true;
        }
        if let Some(v) = args.value("compress.level") {
            // Refused rather than clamped, unlike the serve's read of the same number off the
            // wire. A typo on a command line is a question the caller can still answer; a
            // field in a frame from a peer is not, and silently working less hard is a better
            // answer there than dropping the connection.
            let Ok(n) = v.parse::<u8>() else {
                return fail(format!("-compress.level {v}: a number from 1 to 9"));
            };
            if !(1..=9).contains(&n) {
                return fail(format!("-compress.level {n}: a number from 1 to 9"));
            }
            // AND IT IS REFUSED ON A CODEC THAT HAS NO LEVEL. "Accepted and ignored" is tempting, on
            // the reasoning that refusing the combination would make `-compress.level 9` a trap for
            // anyone who had not also typed `-compress.codec deflate`. But the trap is the SUCCESS: the
            // person who typed a level and no codec is in exactly the position the three lines above
            // describe -- at a terminal, able to answer -- and the run exits 0 having done nothing with
            // the number. There is no reply field echoing the level actually used, so nothing
            // downstream corrects the impression either. Two rules in one option cannot point opposite
            // ways; this is the one that matches the rest of the parser, where `-acl4` with `-noxattr`
            // is a contradiction rather than a no-op.
            if transports.ssh.codec != rcp::remote::proto::Codec::Deflate {
                return fail(format!(
                    "-compress.level {n}: only deflate has levels; add -compress.codec deflate, or drop the level (lz4 is a single-pass format with no effort to trade, and this crate's zstd encoder has one match search)"
                ));
            }
            transports.ssh.level = n;
            transports.ssh.compress = true;
        }
        for (opt, slot) in [
            ("tls.ca", 0),
            ("tls.cert", 1),
            ("tls.key", 2),
            ("tls.clientca", 3),
        ] {
            if let Some(v) = args.value(opt) {
                let p = PathBuf::from(v);
                match slot {
                    0 => transports.ssh.tls.ca = Some(p),
                    1 => transports.ssh.tls.cert = Some(p),
                    2 => transports.ssh.tls.key = Some(p),
                    _ => transports.ssh.tls.client_ca = Some(p),
                }
            }
        }
    }
    // `-acl4` rides in the xattr channel (`system.nfs4_acl`), so asking for it while
    // turning that channel off is a contradiction -- and it was ACCEPTED, silently: the
    // run carried no ACLs and said nothing, which reads like a run that carried them.
    // Refused by name rather than resolved, because either resolution is a guess at which
    // of the two the caller meant.
    if args.has("acl4") {
        for off in ["noxattr", "noattrs"] {
            if args.has(off) {
                return fail(format!("-acl4 carries NFSv4 ACLs in the extended-attribute channel, and -{off} turns that channel off; drop one of the two"));
            }
        }
    }
    #[cfg(all(feature = "nfs", unix))]
    {
        transports.nfs.acl4 = args.has("acl4");
        if let Some(v) = args.value("nfs.sec") {
            match rcp::nfs::rpc::Security::parse(v) {
                Some(s) => transports.nfs.sec = s,
                None => return fail(format!("-nfs.sec {v:?}: use sys, krb5, krb5i or krb5p")),
            }
        }
        if let Some(v) = args.value("nfs.vers") {
            match v.parse::<u32>() {
                Ok(n) if n == 3 || n == 4 => transports.nfs.vers = n,
                _ => return fail(format!("-nfs.vers {v:?}: use 3 or 4")),
            }
        }
        if let Some(v) = args.value("dircount") {
            match parse_size(v) {
                Ok(n) if (1024..=4 << 20).contains(&{ n }) => transports.nfs.dircount = n as u32,
                Ok(_) => return fail("-dircount must be between 1k and 4m"),
                Err(e) => return fail(format!("-dircount {e}")),
            }
        }
    }
    #[cfg(all(feature = "tar", unix))]
    {
        // a tar header carries the owner's NAME beside the id, which is what makes an archive
        // readable on a machine with different ids; the run already has a resolver
        transports.tar.names = Some(args.runtime.names.clone());
        // `.tar.gz` members are independent, so they compress in parallel. The count comes
        // from the run's `-parallel` and not from the machine: a writer that sized its own
        // pool would ignore an operator who asked for one worker, and would also stack its
        // threads on top of the copy's.
        transports.tar.workers = args.parallel().unwrap_or(1);
        // `-rsyncable` cuts those members where the CONTENT says to rather than every 4 MiB,
        // so an edit early in a tree leaves the later members byte-identical and a `-delta` of
        // the archive has something to match. Costs about 0.5% of ratio.
        transports.tar.rsyncable = args.has("rsyncable");
    }
    args.transports = transports;
    let args = &args;
    // redacted, because this fires BEFORE dispatch and therefore before any endpoint is
    // parsed: the refusals that keep a password out of the log all live downstream of here,
    // and a refusal downstream does not unwrite a line upstream. With `-loglevel DEBUG` this
    // wrote the credential into exactly the log the refusals exist to protect.
    rcp::debug!(
        log,
        "{} {}",
        args.command,
        args.positional
            .iter()
            .map(|p| rcp::redact_userinfo(p))
            .collect::<Vec<_>>()
            .join(" ")
    );
    if let Err(e) = writes_allowed(args).and_then(|_| options_allowed(args)) {
        return fail(e);
    }
    // THE DISPATCH -- `tests/describe.rs` reads the command names out of this block, and
    // anchored on `match args.command.as_str()` alone until a second one appeared above
    // and it read five names instead of twenty. The marker is what it anchors on now.
    match args.command.as_str() {
        "help" => {
            let filters = args.sub.as_deref() == Some("filters")
                || ["match", "exclude", "fmt"]
                    .iter()
                    .any(|k| args.values.contains_key(*k) || args.has(k));
            say!(
                "{}",
                if args.sub.as_deref() == Some("info") {
                    INFO_HELP
                } else if filters {
                    FILTERS_HELP
                } else {
                    USAGE
                }
            );
            ExitCode::SUCCESS
        }
        "version" => {
            #[cfg(unix)]
            let uring_available = rcp::uring::available();
            #[cfg(windows)]
            let uring_available = false;
            #[cfg(unix)]
            let kerberos = rcp::gss::available();
            #[cfg(windows)]
            let kerberos: Result<(), String> = Err("Windows GSSAPI is unsupported".into());
            say!(
                "rcp {}",
                env!("CARGO_PKG_VERSION")
            );
            say!("transports: {TRANSPORTS}");
            say!(
                "io_uring: {}",
                if uring_available {
                    "available"
                } else {
                    "unavailable (thread engine will be used)"
                }
            );
            say!(
                "kerberos: {}",
                match kerberos {
                    Ok(()) => "available (the host's GSSAPI library)".to_string(),
                    Err(e) => format!("unavailable: {e}"),
                }
            );
            say!("blake3: the blake3 crate, SIMD kernel chosen at run time");
            say!(
                "sha256: the sha2 crate, {}",
                match rcp::sha256::backend() {
                    rcp::sha256::Backend::HardwareShaNi => "hardware (SHA-NI)",
                    rcp::sha256::Backend::HardwareArmSha2 => "hardware (ARMv8 SHA-2)",
                    rcp::sha256::Backend::Portable => "portable",
                }
            );
            ExitCode::SUCCESS
        }
        "job" => run_job(args, &root),
        // skip(1), not skip(2). The server's rails come from its own argument list, and
        // `skip(2)` assumed `mcp` was argv[1] -- but the parser takes options before the
        // command, so `rcp -allow /safe mcp` handed the server `["/safe", "mcp"]` and the
        // rail was simply gone. Measured: that server answered `rcp_scan` on a path
        // outside the root, while `rcp mcp -allow /safe` refused it. Passing the whole
        // tail is safe because `rails` walks it with the same valued-option grammar and
        // keeps only tokens it recognizes as capabilities -- `mcp` is not one, and the
        // unit test below fails if it ever becomes a valued option name.
        "mcp" => {
            #[cfg(windows)]
            { fail("mcp: Windows process-tree cancellation is not yet qualified") }
            #[cfg(unix)]
            match rcp::mcp::serve(&env::args().skip(1).collect::<Vec<_>>(), VALUED, SWITCHES) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => fail(io_failed("mcp", &e)),
            }
        }
        "describe" => {
            out(format_args!(
                "{}",
                rcp::describe::describe(env!("CARGO_PKG_VERSION"), TRANSPORTS, VALUED, SWITCHES)
            ));
            ExitCode::SUCCESS
        }
        "copy" => run_copy(args, Mode::Fresh, &root),
        "isync" if args.sub.as_deref() == Some("estimate") => run_isync_estimate(args, &root),
        "isync" => run_copy(args, Mode::Mirror, &root),
        "resume" => run_copy(args, Mode::Resume, &root),
        "sync" => run_copy(args, Mode::Sync, &root),
        "verify" => run_verify(args, &root),
        "scan" => run_scan(args, &root),
        "estimate" => run_estimate(args, &root),
        "delete" => run_delete(args, &root),
        "chown" | "chmod" => run_apply(args, &root),
        "diag" => run_diag(args, &root),
        #[cfg(not(all(feature = "remote", unix)))]
        "serve" => fail(
            "serve: this rcp was built without the `remote` feature; rebuild with `--features remote`",
        ),
        #[cfg(all(feature = "remote", unix))]
        "serve" => match args.value("listen") {
            None => match rcp::remote::server::serve(args.runtime.clone()) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => fail(format!("serve: {e}")),
            },
            Some(spec) => {
                // Resolve here rather than inside `listen`: a name that resolves to several
                // addresses has to be narrowed to ONE before the loopback rule can mean
                // anything, and picking the first silently would let a name whose second
                // address is routable pass a check made against its first.
                let addrs: Vec<std::net::SocketAddr> =
                    match std::net::ToSocketAddrs::to_socket_addrs(&spec) {
                        Ok(it) => it.collect(),
                        Err(e) => return fail(format!("serve -listen {spec}: {e}")),
                    };
                let [addr] = addrs[..] else {
                    return fail(format!(
                        "serve -listen {spec}: resolves to {} addresses; name exactly one",
                        addrs.len()
                    ));
                };
                match rcp::remote::server::listen(
                    args.runtime.clone(),
                    addr,
                    &allowed_roots(args),
                    &args.transports.ssh.tls,
                    |bound| eprintln!("serve: listening on {bound}"),
                ) {
                    Ok(()) => ExitCode::SUCCESS,
                    Err(e) => fail(format!("serve: {e}")),
                }
            }
        },
        "copybatch" => run_copybatch(args),
        "scanbatch" => run_scanbatch(args),
        #[cfg(not(all(feature = "nfs", unix)))]
        "show" if !args.positional.is_empty() => fail(
            "show HOST: this rcp was built without the `nfs` feature; rebuild with `--features nfs`",
        ),
        #[cfg(all(feature = "nfs", unix))]
        "show" if !args.positional.is_empty() => {
            let mut failed = 0;
            for host in args
                .positional
                .iter()
                .flat_map(|p| p.split(','))
                .map(str::trim)
                .filter(|h| !h.is_empty())
            {
                // `show` takes an NFS HOST, and neither a scheme nor userinfo is part of
                // one. Refused here rather than handed to the resolver, because every
                // message below quotes the token back: `rcp show
                // 'dav://user:hunter2@host/path'` printed the password into the run's
                // output and into whatever log caught it, which is exactly what the
                // endpoint refusals in `lib.rs` exist to prevent. Measured before the fix.
                //
                // The refusal does not quote it either, for the same reason.
                if host.contains("://") {
                    say!("ERROR: show takes an NFS host, not a URL (the URL is not repeated here, in case it carries a password). Use `rcp scan URL` to list a remote tree");
                    failed += 1;
                    continue;
                }
                if host.contains('@') {
                    say!("ERROR: show takes an NFS host, and a user does not go in one (the token is not repeated here, in case it carries a password)");
                    failed += 1;
                    continue;
                }
                match rcp::nfs::show::show(host, args.has("v")) {
                    Ok(report) => sayp!("{}", report.render()),
                    Err(e) => {
                        say!("ERROR: show {host}: {e}");
                        failed += 1;
                    }
                }
            }
            if failed > 0 {
                fail(format!("show: {failed} host(s) did not answer"))
            } else {
                pass()
            }
        }
        "show" => match rcp::mounts::mounts() {
            Ok(all) => {
                let shown: Vec<_> = all
                    .iter()
                    .filter(|m| args.has("all") || m.is_network())
                    .collect();
                say!(
                    "{:<32} {:<10} {:<40} options",
                    "mount point",
                    "type",
                    "source"
                );
                for m in &shown {
                    say!(
                        "{:<32} {:<10} {:<40} {}",
                        m.target,
                        m.fstype,
                        m.source,
                        m.options
                    );
                }
                say!(
                    "show: {} of {} mounted filesystems{}",
                    shown.len(),
                    all.len(),
                    if args.has("all") {
                        ""
                    } else {
                        " (network types; -all for every mount)"
                    }
                );
                pass()
            }
            Err(e) => fail(format!("show: {e}")),
        },
        "indexlist" => match Catalog::list(&root) {
            Ok(infos) => {
                let mut unreadable = 0usize;
                for i in &infos {
                    // A torn index prints as "unreadable", NOT as "0 entries". The two are
                    // opposite facts -- an empty catalog is fine and a destroyed one is not --
                    // and printing both the same way under STATUS: PASSED is what let a crashed
                    // catalog survey as healthy.
                    let entries = match i.entries {
                        Some(n) => format!("{n} entries"),
                        None => {
                            unreadable += 1;
                            "unreadable".to_string()
                        }
                    };
                    say!("{}\t{}\t{} -> {}", i.id, entries, i.source, i.destination);
                }
                say!(
                    "indexlist: {} catalogs under {}",
                    infos.len(),
                    root.display()
                );
                if unreadable > 0 {
                    fail(format!(
                        "indexlist: {unreadable} of {} catalogs have an unreadable index",
                        infos.len()
                    ))
                } else {
                    pass()
                }
            }
            Err(e) => fail(format!("indexlist: {e}")),
        },
        "indexdelete" => {
            let ids: Vec<String> = if let Some(id) = args.value("id") {
                vec![id.to_string()]
            } else if !args.all("match").is_empty() {
                match Catalog::ids_matching(&root, &args.all("match")) {
                    Ok(ids) => ids,
                    Err(e) => return fail(format!("indexdelete: {e}")),
                }
            } else {
                return fail("indexdelete needs -id ID or -match GLOB");
            };
            if ids.is_empty() {
                return fail("indexdelete: no catalog matches");
            }
            for id in &ids {
                if let Err(e) = Catalog::delete(&root, id) {
                    return fail(format!("indexdelete: {e}"));
                }
                say!("indexdelete: removed catalog {id}");
                let job = Job {
                    root: root.clone(),
                    command: "indexdelete",
                    id: id.clone(),
                    source: String::new(),
                    destination: String::new(),
                    started: Instant::now(),
                };
                job.log("PASSED", "catalog removed");
            }
            pass()
        }
        "logdump" => run_logdump(args, &root),
        "license" | "activate" => {
            say!("rcp requires no activation; licensed under Apache-2.0");
            pass()
        }
        other => {
            say!("{USAGE}");
            fail(format!("unknown command {other:?}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authorities(argv: &[&str]) -> Vec<String> {
        let raw: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
        let args = parse_args(raw).expect("the arguments parse");
        match away_policy(&args).expect("the roots read") {
            rcp::ports::Away::Only(list) => list.to_vec(),
            rcp::ports::Away::Anywhere => {
                panic!("a railed run must not follow a hand-off anywhere")
            }
        }
    }

    /// Where a registry may hand this run's uploads on to, derived from `-allow`.
    ///
    /// A unit test rather than a contract arm, and that was not the first choice: the
    /// contract arm written for this could not fail. It binds the stand-in's away listener
    /// on a random high port, and the defect below only bites on 80 or 443, so planting it
    /// back left the arm green. An arm that cannot fail is worse than no arm, because it
    /// reads as coverage. The function is pure -- arguments in, a list of authorities out
    /// -- so this measures it directly.
    #[test]
    fn a_port_the_operator_wrote_is_the_port_the_hand_off_may_use() {
        // `oci` is rcp's spelling, never a scheme on the wire: a root is translated to the
        // scheme it will really be spoken in
        assert_eq!(
            authorities(&[
                "scan",
                "-allow",
                "oci://reg.example/app",
                "oci://reg.example/app"
            ]),
            ["https://reg.example:443"]
        );
        assert_eq!(
            authorities(&[
                "scan",
                "-oci.insecure",
                "-allow",
                "oci://reg.example/app",
                "oci://reg.example/app"
            ]),
            ["http://reg.example:80"]
        );
        // an explicit port is kept, INCLUDING 80 and 443. The first version rewrote those
        // two to each other, so `-allow oci://h:80` came out `https://h:443`: it admitted a
        // place the operator did not name and refused the one they did
        assert_eq!(
            authorities(&[
                "scan",
                "-allow",
                "oci://reg.example:80/app",
                "oci://reg.example:80/app"
            ]),
            ["https://reg.example:80"]
        );
        assert_eq!(
            authorities(&[
                "scan",
                "-oci.insecure",
                "-allow",
                "oci://reg.example:443/app",
                "oci://reg.example:443/app"
            ]),
            ["http://reg.example:443"]
        );
        assert_eq!(
            authorities(&[
                "scan",
                "-allow",
                "oci://reg.example:5000/app",
                "oci://reg.example:5000/app"
            ]),
            ["https://reg.example:5000"]
        );
        // `hdfs` is rcp's spelling too, and WebHDFS is plain HTTP: a namenode reached over
        // TLS is written `https://` in the first place. The port is the one the operator
        // wrote, which for a namenode is always written, because 9870 is nobody's default.
        assert_eq!(
            authorities(&[
                "scan",
                "-allow",
                "hdfs://nn.example:9870/data",
                "hdfs://nn.example:9870/data"
            ]),
            ["http://nn.example:9870"]
        );
        assert_eq!(
            authorities(&[
                "scan",
                "-allow",
                "https://nn.example:9871/data",
                "hdfs://nn.example:9870/data"
            ]),
            ["https://nn.example:9871"]
        );
        // a root of any other scheme is taken as written, with that scheme's default port
        assert_eq!(
            authorities(&[
                "scan",
                "-allow",
                "https://storage.example/b",
                "oci://reg.example/app"
            ]),
            ["https://storage.example:443"]
        );
        assert_eq!(
            authorities(&[
                "scan",
                "-allow",
                "http://storage.example/b",
                "oci://reg.example/app"
            ]),
            ["http://storage.example:80"]
        );
        // a local root names no authority at all, and must not silently become one
        assert!(authorities(&["scan", "-allow", "/data", "/data"]).is_empty());
        // nor does a root whose scheme is never spoken on an HTTP wire: `s3://bucket:443`
        // is an entry no `Location` and no realm can ever match
        assert!(authorities(&["scan", "-allow", "s3://bucket/p", "s3://bucket/p"]).is_empty());
        assert!(
            authorities(&["scan", "-allow", "nfs://filer/export", "nfs://filer/export"]).is_empty()
        );
        // A port that is all digits and does not fit a u16 is NOT a port, and the rail
        // refuses rather than filling in the scheme's default. `.parse().ok()` would do
        // the latter: `-allow https://host:99999` would produce `https://host:443` -- a
        // place the operator never named -- which is the one direction a rail must never
        // move on its own. 65535 is the boundary and is
        // legal; 65536 is the first that is not.
        for root in [
            "https://host:99999",
            "https://host:65536",
            "oci://reg.example:70000/app",
            "hdfs://nn:99999/d",
        ] {
            let raw: Vec<String> = ["scan", "-allow", root, "https://host/x"]
                .iter()
                .map(|s| s.to_string())
                .collect();
            let e = away_policy(&parse_args(raw).unwrap())
                .err()
                .unwrap_or_else(|| panic!("{root} was accepted"));
            let text = format!("{e:?}");
            assert!(
                text.contains("is not a number"),
                "{root}: the refusal does not say what is wrong: {text}"
            );
        }
        // the control, and it is what says the check is about the RANGE rather than about
        // long ports: the largest legal port is kept exactly as written
        assert_eq!(
            authorities(&[
                "scan",
                "-allow",
                "https://host:65535/b",
                "https://host:65535/b"
            ]),
            ["https://host:65535"]
        );

        // and the control on the whole mechanism: with no rails there is no list to be on
        let raw: Vec<String> = ["scan", "oci://reg.example/app"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert!(matches!(
            away_policy(&parse_args(raw).unwrap()),
            Ok(rcp::ports::Away::Anywhere)
        ));
    }

    /// The MCP server is handed `env::args().skip(1)`, which includes the word `mcp`.
    /// That is only safe while `mcp` is not a valued option name: `rails` walks the list
    /// with the valued grammar, so a valued `mcp` would swallow the token after it and
    /// drop a rail. Nothing else would notice -- the server would start, answer, and
    /// quietly be missing a root -- so the invariant is asserted rather than remembered.
    ///
    /// The same holds for every other bare word a command line can carry in that
    /// position, but `mcp` is the only one reached this way.
    #[test]
    fn the_command_word_is_not_an_option_name() {
        for command in [
            "mcp", "copy", "scan", "sync", "resume", "verify", "job", "diag", "serve", "describe",
        ] {
            assert!(!VALUED.contains(&command), "-{command} takes a value, so the command word {command:?} would eat the token after it");
            assert!(
                !SWITCHES.contains(&command),
                "-{command} is a switch, so the command word {command:?} would be relayed as one"
            );
        }
    }
}
