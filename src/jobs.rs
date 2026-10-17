//! `rcp job`: a copy that outlives the call that started it.
//!
//! A tool call that waits for a terabyte is a tool call that times out, and an agent that
//! cannot let go of a transfer cannot do anything else while it runs. `rcp job start`
//! launches the command in its own session, writes down where its events are going, and
//! returns an id; `status`, `wait`, `log` and `cancel` work from that id afterwards, from
//! any process, including one started after the job was.
//!
//! Nothing here is a daemon. The job is the ordinary command with its output redirected to
//! a file, in a session of its own so a closing terminal or a dying agent host does not
//! take it with it. That is why a canceled job is resumable: it was always just `rcp`,
//! and the catalog it was writing is the one `rcp resume` reads.

use std::fs;
use std::io::{self, BufRead, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::json::{self, quote, Json};

extern "C" {
    fn setsid() -> i32;
    fn kill(pid: i32, sig: i32) -> i32;
}

const SIGTERM: i32 = 15;
const SIGKILL: i32 = 9;

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
struct ProcessHandle(std::os::fd::OwnedFd);

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
impl ProcessHandle {
    fn open(pid: i32) -> io::Result<Self> {
        use std::os::fd::FromRawFd;
        extern "C" {
            fn syscall(number: std::ffi::c_long, ...) -> std::ffi::c_long;
        }
        // Linux x86-64 and AArch64 use syscall 434 for pidfd_open.
        // SAFETY: the architecture-gated syscall number and integer argument types match
        // pidfd_open(pid_t, unsigned int); no userspace pointer is passed to the kernel.
        let fd = unsafe { syscall(434, pid, 0u32) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: this successful syscall returns a new, uniquely owned descriptor.
        Ok(Self(unsafe {
            std::os::fd::OwnedFd::from_raw_fd(fd as i32)
        }))
    }

    fn signal(&self, signal: i32) -> io::Result<()> {
        use std::os::fd::AsRawFd;
        extern "C" {
            fn syscall(number: std::ffi::c_long, ...) -> std::ffi::c_long;
        }
        // SAFETY: a null siginfo requests normal signal semantics; the descriptor pins
        // the process identity even if its numeric PID has since been reused.
        let result = unsafe {
            syscall(
                424,
                self.0.as_raw_fd(),
                signal,
                std::ptr::null::<std::ffi::c_void>(),
                0u32,
            )
        };
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(3) {
                // ESRCH: the pinned process already exited.
                return Err(error);
            }
        }
        Ok(())
    }
}

/// Where a job's file, events and messages live.
/// Creates a job file readable by its owner alone.
///
/// The job record holds the argv of a running copy -- endpoints, hosts, catalog ids -- and
/// its event and message streams hold every path the run touched. Written with
/// `fs::write` and `File::create` these landed at the process umask, so 0644 on the usual
/// one. `redact_credentials` keeps the SECRET out of the record; it says nothing about who
/// may read the rest, and on a shared host the rest is the interesting part.
fn private_create(path: &Path) -> io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
}

fn private_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    private_create(path)?.write_all(bytes)
}

fn private_create_new(path: &Path) -> io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

pub struct Jobs {
    dir: PathBuf,
}

/// What is known about a job: what it was asked to do, where it went, and how it ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Job {
    pub id: String,
    pub argv: Vec<String>,
    pub pid: i32,
    pub started: u64,
    /// The kernel's start time for `pid`, in clock ticks since boot, read from
    /// `/proc/<pid>/stat` when the job was spawned. `None` on a record written before this
    /// field existed, or where `/proc` is not mounted.
    ///
    /// A pid is not an identity. It is a small integer the kernel hands out again, and
    /// `cancel` signaled whatever pid the record named after checking only that something
    /// with that number was alive -- so a job that had already exited, whose pid had been
    /// reused by an unrelated process, got that process SIGTERM and then SIGKILL. No
    /// attacker is needed for this, just a busy machine and a stale record. `(pid,
    /// starttime)` IS an identity: the kernel cannot reissue the pair.
    pub pid_start: Option<u64>,
    /// `running`, `passed`, `failed` or `canceled`, as of the last time it was read.
    pub state: String,
    /// The catalog id the job was given, so a canceled job can be resumed.
    pub catalog: Option<String>,
}

/// The kernel's start time for `pid`, in clock ticks since boot.
///
/// Field 22 of `/proc/<pid>/stat`. The parse starts after the LAST `)` because field 2 is
/// the executable name in parentheses and an executable may be named `foo) 1 2 3 (bar`.
fn proc_start(pid: i32) -> Option<u64> {
    let text = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let rest = &text[text.rfind(')')? + 1..];
    // after the comm field the next is state, so starttime (field 22) is the 20th token
    rest.split_whitespace().nth(19)?.parse().ok()
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// An id unique across rapid starts in this process, including clock adjustments.
fn new_id(pid: u32) -> String {
    static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let sequence = SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("job-{nanos}-{pid}-{sequence}")
}

fn field(doc: &Json, key: &str) -> String {
    doc.get(key)
        .and_then(Json::as_str)
        .unwrap_or_default()
        .to_string()
}

impl Jobs {
    /// The jobs directory beside the catalog: one file per job, named by its id.
    /// Construction does not create directories or start processes.
    ///
    /// ```
    /// use rcp::jobs::Jobs;
    /// use std::path::Path;
    /// let jobs = Jobs::at(Path::new("catalog"));
    /// assert_eq!(jobs.events("job-123")?, Path::new("catalog/jobs/job-123.ndjson"));
    /// assert_eq!(jobs.events("../outside").unwrap_err().kind(), std::io::ErrorKind::InvalidInput);
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn at(root: &Path) -> Jobs {
        Jobs {
            dir: root.join("jobs"),
        }
    }

    /// Every path under the jobs directory is built here, and every one of them is
    /// checked. The id arrives from a command line or from an agent's JSON, so
    /// `job cancel ../../elsewhere/victim` is a request anyone can make: it reads a
    /// job record from outside the jobs directory, and `cancel` then sends SIGTERM and
    /// SIGKILL to whatever pid that record names. A planted record is a way to signal
    /// any process of this user.
    ///
    /// The three builders return `Result` rather than taking the check on trust at each
    /// call site, so a path under `dir` cannot be constructed without passing it --
    /// which is what makes this a choke point instead of seven reminders.
    fn checked(&self, id: &str) -> io::Result<()> {
        if crate::catalog::Catalog::valid_id(id) {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("job id {id:?} is not a valid name; `rcp job list` names them"),
            ))
        }
    }

    fn file(&self, id: &str) -> io::Result<PathBuf> {
        self.checked(id)?;
        Ok(self.dir.join(format!("{id}.json")))
    }

    pub fn events(&self, id: &str) -> io::Result<PathBuf> {
        self.checked(id)?;
        Ok(self.dir.join(format!("{id}.ndjson")))
    }

    pub fn messages(&self, id: &str) -> io::Result<PathBuf> {
        self.checked(id)?;
        Ok(self.dir.join(format!("{id}.log")))
    }

    fn write(&self, job: &Job) -> io::Result<()> {
        let argv: Vec<String> = job.argv.iter().map(|a| quote(a)).collect();
        let text = format!(
            "{{\"id\": {}, \"pid\": {}, \"pid_start\": {}, \"started\": {}, \"state\": {}, \"catalog\": {}, \"argv\": [{}]}}\n",
            quote(&job.id),
            job.pid,
            job.pid_start.map(|t| t.to_string()).unwrap_or_else(|| "null".into()),
            job.started,
            quote(&job.state),
            job.catalog.as_ref().map(|c| quote(c)).unwrap_or_else(|| "null".into()),
            argv.join(", ")
        );
        private_write(&self.file(&job.id)?, text.as_bytes())
    }

    /// Reads a stored job record without checking whether its process is still running.
    /// Use [`Self::status`] to reconcile the record with process identity and events.
    ///
    /// # Errors
    ///
    /// Returns an invalid-ID or filesystem error, or [`io::ErrorKind::InvalidData`] for
    /// malformed JSON. Missing optional fields retain backward-compatible defaults.
    pub fn read(&self, id: &str) -> io::Result<Job> {
        let text = fs::read(self.file(id)?)
            .map_err(|e| io::Error::new(e.kind(), format!("job {id}: {e}")))?;
        let doc = json::parse(&text)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("job {id}: {e}")))?;
        Ok(Job {
            id: field(&doc, "id"),
            pid: doc.get("pid").and_then(Json::as_i64).unwrap_or(0) as i32,
            pid_start: doc.get("pid_start").and_then(Json::as_u64),
            started: doc.get("started").and_then(Json::as_u64).unwrap_or(0),
            state: field(&doc, "state"),
            catalog: doc
                .get("catalog")
                .and_then(Json::as_str)
                .map(str::to_string)
                .filter(|c| !c.is_empty()),
            argv: doc
                .get("argv")
                .and_then(Json::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default(),
        })
    }

    pub fn list(&self) -> io::Result<Vec<Job>> {
        let mut out = Vec::new();
        let Ok(entries) = fs::read_dir(&self.dir) else {
            return Ok(out);
        };
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if let Some(id) = name.strip_suffix(".json") {
                if let Ok(j) = self.read(id) {
                    out.push(j);
                }
            }
        }
        out.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(out)
    }

    /// Starts `argv` as a job of its own: a session of its own so nothing that closes here
    /// reaches it, events to one file and messages to another, and the job file written
    /// before the id is returned so a `status` immediately after `start` finds it.
    /// `valued` is the parser's list of options that take a separate value, so the
    /// credential walk below reads the arguments with the same grammar the parser does.
    ///
    /// # Errors
    ///
    /// Propagates directory/log creation, process spawning/session setup, or job-record
    /// write failures. If recording a spawned job fails, its new process group is stopped
    /// and the direct child is reaped before the error is returned. Cleanup failures are
    /// included in the returned error.
    pub fn start(
        &self,
        exe: &Path,
        argv: &[String],
        catalog_root: &Path,
        valued: &[&str],
    ) -> io::Result<Job> {
        fs::create_dir_all(&self.dir)?;
        // -json so the events are parseable afterwards, and the catalog this run's `job`
        // subcommand was given, so the child and its reader agree where the catalog is
        let mut full: Vec<String> = vec![
            "-catalog".into(),
            catalog_root.display().to_string(),
            "-json".into(),
        ];
        // A CREDENTIAL GOES IN THE ENVIRONMENT, NOT ON THE CHILD'S COMMAND LINE. `-dav.user
        // alice:PASSWORD` reached `ps` for the whole life of a detached job, which for a
        // large copy is hours, and any user on the host could read it. The same split the
        // MCP server already makes for the same reason: the command line is what a caller
        // writes and an operator reads, the environment is the process's own.
        //
        // An option whose value cannot be relayed (no reader for its variable) stays on
        // the command line rather than being dropped -- a credential silently discarded is
        // a run that goes out unauthenticated believing otherwise, which is worse.
        let mut env: Vec<(String, String)> = Vec::new();
        let mut kept: Vec<String> = Vec::new();
        let mut i = 0;
        while i < argv.len() {
            let arg = &argv[i];
            let name = arg.trim_start_matches('-');
            let takes_value = arg.starts_with('-') && valued.contains(&name);
            let secret = arg.starts_with('-')
                && crate::describe::capability_of(name)
                    == Some(crate::describe::Capability::Credential);
            match (
                secret,
                takes_value,
                crate::mcp::relay_env(name),
                argv.get(i + 1),
            ) {
                (true, true, Some(var), Some(v)) => {
                    env.push((var.to_string(), v.clone()));
                    i += 2;
                }
                _ => {
                    kept.push(arg.clone());
                    i += 1;
                    if takes_value {
                        if let Some(v) = argv.get(i) {
                            kept.push(v.clone());
                            i += 1;
                        }
                    }
                }
            }
        }
        full.extend(kept);
        let id = new_id(std::process::id());
        // Reserve new logs rather than truncating another job after an ID collision.
        let out = private_create_new(&self.events(&id)?)?;
        let err = private_create_new(&self.messages(&id)?)?;
        let mut cmd = Command::new(exe);
        cmd.args(&full)
            .envs(env)
            .stdin(Stdio::null())
            .stdout(Stdio::from(out))
            .stderr(Stdio::from(err));
        // SAFETY: setsid in the child between fork and exec, which is async-signal-safe.
        // Without it the job shares this session and a terminal that closes, or a host
        // that kills its process group, takes the copy with it.
        unsafe {
            std::os::unix::process::CommandExt::pre_exec(&mut cmd, || {
                if setsid() == -1 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            })
        };
        let mut child = cmd
            .spawn()
            .map_err(|e| io::Error::new(e.kind(), format!("starting the job: {e}")))?;
        let catalog = argv
            .windows(2)
            .find(|w| w[0] == "-newid" || w[0] == "-id")
            .map(|w| w[1].clone());
        // and the RECORD is redacted too, because `<catalog>/jobs/<id>.json` is written to
        // disk and read back by `job status`, `job list`, `job wait`, `job cancel` and
        // `job forget` -- five subcommands that printed the credential to whoever ran
        // them, from a file that outlives the run.
        let job = Job {
            id: id.clone(),
            argv: crate::describe::redact_credentials(argv, valued),
            pid: child.id() as i32,
            pid_start: proc_start(child.id() as i32),
            started: now(),
            state: "running".into(),
            catalog,
        };
        self.record_started_job(&mut child, &job)?;
        Ok(job)
    }

    /// The child has just successfully exec'd after setsid and has not been waited on.
    /// Holding it unreaped keeps its PID (and therefore this new group's ID) from reuse.
    fn record_started_job(&self, child: &mut Child, job: &Job) -> io::Result<()> {
        if let Err(record_error) = self.write(job) {
            let mut failures = Vec::new();
            // SAFETY: setsid made the owned direct child's positive PID its group ID.
            // It has not been reaped, so this ID cannot name an unrelated new group.
            // Signal the whole group before wait, including subprocesses already started.
            if unsafe { kill(-(child.id() as i32), SIGKILL) } != 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(3) {
                    failures.push(format!("stopping the job group: {error}"));
                }
            }
            // Also stop the owned leader if it changed its group after exec. Child's PID
            // is still reserved by our unreaped parent-child relationship at this point.
            if let Err(error) = child.kill() {
                if error.raw_os_error() != Some(3) {
                    failures.push(format!("stopping the job process: {error}"));
                }
            }
            if let Err(error) = child.wait() {
                failures.push(format!("reaping the job process: {error}"));
            }
            if failures.is_empty() {
                return Err(record_error);
            }
            return Err(io::Error::new(
                record_error.kind(),
                format!("{record_error}; cleanup failed: {}", failures.join("; ")),
            ));
        }
        Ok(())
    }

    /// The job as it is now: the file's record, corrected by what the process and its
    /// events say. A job file says `running` forever on its own, because nothing updates
    /// it when the child exits; the events and the process do know.
    ///
    /// # Errors
    ///
    /// Propagates record-read, event-read or updated-record write errors. See [`Self::read`]
    /// for invalid IDs and malformed stored records.
    pub fn status(&self, id: &str) -> io::Result<Job> {
        let mut job = self.read(id)?;
        if job.state != "running" {
            return Ok(job);
        }
        match self.final_status(id)? {
            Some(s) => {
                job.state = s;
                self.write(&job)?;
            }
            None if !self.is_job(&job) => {
                // gone without a done event: killed, or died before it could say so
                job.state = "canceled".into();
                self.write(&job)?;
            }
            None => {}
        }
        Ok(job)
    }

    /// `passed` or `failed` from the run's own last `done` event, or `None` while it has
    /// not reached one.
    fn final_status(&self, id: &str) -> io::Result<Option<String>> {
        let path = self.events(id)?;
        let Ok(file) = fs::File::open(&path) else {
            return Ok(None);
        };
        let mut last = None;
        for line in io::BufReader::new(file).lines() {
            let line = line?;
            if let Ok(doc) = json::parse(line.as_bytes()) {
                if doc.get("event").and_then(Json::as_str) == Some("done") {
                    last = doc.get("status").and_then(Json::as_str).map(str::to_string);
                }
            }
        }
        Ok(last)
    }

    /// Whether the process is still there. `kill(pid, 0)` asks without sending anything.
    /// Whether the job's process -- not merely SOME process with that number -- is alive.
    ///
    /// `kill(pid, 0)` answers "is any process numbered `pid` alive", which is a different
    /// question and the one `cancel` used to ask. A job that exited long ago leaves a
    /// record naming a pid the kernel has since handed to something else, and signaling
    /// that is how an unrelated process gets killed by a `job cancel` on a stale id.
    ///
    /// Where `/proc` gives a start time and the record has one, the pair must match. Where
    /// either is missing the old behavior stands -- there is no better answer available,
    /// and refusing to cancel anything on a system without `/proc` would break the feature
    /// to fix a narrower problem than the one that creates.
    fn is_job(&self, job: &Job) -> bool {
        // SAFETY: a positive PID selects one process; signal zero only probes existence
        // and permission. This FFI call has no pointer or memory-lifetime requirements.
        if job.pid <= 0 || unsafe { kill(job.pid, 0) } != 0 {
            return false;
        }
        match (job.pid_start, proc_start(job.pid)) {
            (Some(recorded), Some(now)) => recorded == now,
            _ => true,
        }
    }

    /// Waits for the job to leave `running`, checking every `every` up to `limit`.
    /// Returns the job either way, so a caller that timed out still sees where it got to.
    ///
    /// # Errors
    ///
    /// Propagates errors from [`Self::status`]. Reaching the timeout is not an error.
    ///
    /// # Panics
    ///
    /// Panics if adding `limit` to the current monotonic clock exceeds its supported range.
    pub fn wait(&self, id: &str, every: Duration, limit: Duration) -> io::Result<Job> {
        let deadline = std::time::Instant::now() + limit;
        loop {
            let job = self.status(id)?;
            if job.state != "running" || std::time::Instant::now() >= deadline {
                return Ok(job);
            }
            std::thread::sleep(every);
        }
    }

    /// Asks the job to stop, then insists. The copy leaves its catalog behind, so
    /// `rcp resume -id <catalog>` finishes what it started.
    ///
    /// # Errors
    ///
    /// Propagates record/event I/O and signal permission errors. On Linux x86-64/AArch64,
    /// cancellation requires `pidfd_open`; unsupported kernels or blocked syscalls return
    /// an error rather than using the PID-reuse-prone fallback. Other Unix targets retain
    /// start-time identity checks where available, with a check-to-signal race.
    pub fn cancel(&self, id: &str) -> io::Result<Job> {
        let mut job = self.status(id)?;
        if job.state != "running" {
            return Ok(job);
        }
        // Pin the process BEFORE checking /proc identity. All later signals use this
        // handle, so a PID recycled between the check and a signal cannot be targeted.
        // A kernel without pidfd support refuses cancellation rather than silently
        // falling back to the Linux check/signal race.
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        let handle = match ProcessHandle::open(job.pid) {
            Ok(handle) => Some(handle),
            Err(e) if e.raw_os_error() == Some(3) => None,
            Err(e) => {
                return Err(io::Error::new(
                    e.kind(),
                    format!("safe job cancellation needs pidfd_open: {e}"),
                ))
            }
        };
        if !self.is_job(&job) {
            // the record says running and the process is not this job's: it exited without
            // recording an outcome, and its pid may now belong to something else
            job.state = self.final_status(id)?.unwrap_or_else(|| "canceled".into());
            self.write(&job)?;
            return Ok(job);
        }
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        let signal = |sig| match &handle {
            Some(handle) => handle.signal(sig),
            None => Ok(()),
        };
        // Other Unix targets retain the process-identity check available there.
        #[cfg(not(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )))]
        let signal = |sig| {
            // SAFETY: is_job requires a positive PID and validates available start-time
            // identity; sig is one of our fixed signal constants and no pointers are used.
            // This portable fallback still has a check/signal race; supported Linux
            // targets use the pinned pidfd above to avoid signaling a later PID reuser.
            if self.is_job(&job) && unsafe { kill(job.pid, sig) } != 0 {
                let e = io::Error::last_os_error();
                if e.raw_os_error() != Some(3) {
                    return Err(e);
                }
            }
            Ok(())
        };
        signal(SIGTERM)?;
        for _ in 0..40 {
            if !self.is_job(&job) {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        if self.is_job(&job) {
            signal(SIGKILL)?;
            std::thread::sleep(Duration::from_millis(100));
        }
        job.state = self.final_status(id)?.unwrap_or_else(|| "canceled".into());
        self.write(&job)?;
        Ok(job)
    }

    /// The job's events, from `from` bytes in, with the offset to read from next. An agent
    /// polling a running job asks for what it has not seen rather than the whole file.
    /// Missing or unopenable event files currently return empty text and offset zero.
    ///
    /// # Errors
    ///
    /// Returns an invalid-ID error or propagates metadata, seek and UTF-8 read failures.
    /// Supply the byte offset returned by the previous call; arbitrary offsets may split
    /// a UTF-8 character and fail decoding. Incomplete final lines are left for later reads.
    pub fn log(&self, id: &str, from: u64) -> io::Result<(String, u64)> {
        let path = self.events(id)?;
        let Ok(mut file) = fs::File::open(&path) else {
            return Ok((String::new(), 0));
        };
        let len = file.metadata()?.len();
        if from >= len {
            return Ok((String::new(), len));
        }
        file.seek(SeekFrom::Start(from))?;
        let mut text = String::new();
        file.read_to_string(&mut text)?;
        // a partial last line would not parse, so it is left for the next read
        match text.rfind('\n') {
            Some(i) => Ok((text[..=i].to_string(), from + i as u64 + 1)),
            None => Ok((String::new(), from)),
        }
    }

    /// What the run said to a person, which is where a failure explains itself.
    pub fn messages_text(&self, id: &str) -> String {
        self.messages(id)
            .and_then(fs::read_to_string)
            .unwrap_or_default()
    }

    /// Removes a job's file, events and messages. Refuses one that is still running,
    /// because forgetting a job does not stop it and a forgotten copy is worse than a
    /// listed one.
    pub fn forget(&self, id: &str) -> io::Result<()> {
        let job = self.status(id)?;
        if job.state == "running" {
            return Err(io::Error::new(
                io::ErrorKind::ResourceBusy,
                format!("job {id} is still running; cancel it first"),
            ));
        }
        let _ = fs::remove_file(self.events(id)?);
        let _ = fs::remove_file(self.messages(id)?);
        fs::remove_file(self.file(id)?)
    }
}

/// One job as a line a person reads.
pub fn line(job: &Job) -> String {
    format!(
        "{}\t{}\t{}\t{}",
        job.id,
        job.state,
        job.catalog.as_deref().unwrap_or("-"),
        job.argv.join(" ")
    )
}

/// One job as the fields an event carries.
pub fn fields(job: &Job) -> Vec<(&'static str, String)> {
    vec![
        ("job", job.id.clone()),
        ("state", job.state.clone()),
        ("pid", job.pid.to_string()),
        ("catalog", job.catalog.clone().unwrap_or_default()),
        ("command", job.argv.join(" ")),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn an_unrecordable_job_stops_its_group_and_reaps_its_child() {
        let root = scratch("record-failure");
        let jobs = Jobs::at(&root);
        fs::create_dir_all(&jobs.dir).unwrap();
        // A directory at the exact record filename makes the write fail deterministically,
        // without racing filesystem permissions, clocks, or another test's global state.
        fs::create_dir(jobs.file("failed").unwrap()).unwrap();
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "sleep 30 & echo $!; wait"]);
        command.stdout(Stdio::piped());
        // SAFETY: setsid is async-signal-safe and runs in our newly forked child.
        unsafe {
            std::os::unix::process::CommandExt::pre_exec(&mut command, || {
                if setsid() == -1 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command.spawn().unwrap();
        let mut descendant = String::new();
        io::BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut descendant)
            .unwrap();
        let descendant: i32 = descendant.trim().parse().unwrap();
        let pid = child.id() as i32;
        let job = Job {
            id: "failed".into(),
            argv: vec!["scan".into()],
            pid,
            pid_start: proc_start(pid),
            started: now(),
            state: "running".into(),
            catalog: None,
        };
        // Reproduce the old failure: writing the record fails while its child is alive.
        assert!(jobs.write(&job).is_err());
        assert!(child.try_wait().unwrap().is_none());
        assert!(jobs.record_started_job(&mut child, &job).is_err());
        assert!(
            child.try_wait().unwrap().is_some(),
            "the leader was left running"
        );
        assert!(
            !Path::new(&format!("/proc/{pid}")).exists(),
            "the leader was not reaped"
        );
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            let stat = fs::read_to_string(format!("/proc/{descendant}/stat"));
            let stopped = match stat {
                Err(_) => true,
                Ok(stat) => stat
                    .rsplit_once(')')
                    .is_some_and(|(_, rest)| rest.trim_start().starts_with('Z')),
            };
            if stopped {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "a job descendant survived the failed record write"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        // The failure fixture itself must not be deleted by cleanup.
        assert!(jobs.file("failed").unwrap().is_dir());
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn cancellation_signals_only_the_recorded_child() {
        let root = scratch("pidfd-cancel");
        let jobs = Jobs::at(&root);
        fs::create_dir_all(&jobs.dir).unwrap();
        let me = std::process::id() as i32;
        let stale = Job {
            id: "stale".into(),
            argv: vec!["scan".into()],
            pid: me,
            pid_start: Some(proc_start(me).unwrap() + 1),
            started: 1,
            state: "running".into(),
            catalog: None,
        };
        jobs.write(&stale).unwrap();
        assert_eq!(jobs.cancel("stale").unwrap().state, "canceled");

        let mut child = Command::new("sleep").arg("30").spawn().unwrap();
        let pid = child.id() as i32;
        let job = Job {
            id: "child".into(),
            pid,
            pid_start: Some(proc_start(pid).unwrap()),
            state: "running".into(),
            ..stale
        };
        jobs.write(&job).unwrap();
        let outcome = jobs.cancel("child");
        let stopped = child.try_wait().unwrap();
        // Always clean up the one child this test owns, including unsupported kernels.
        let _ = child.kill();
        let exit = child.wait().unwrap();
        assert_eq!(outcome.unwrap().state, "canceled");
        assert!(
            stopped.is_some(),
            "cancel must stop the child before reporting completion"
        );
        assert!(!exit.success());
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn a_process_handle_cannot_signal_after_its_child_is_reaped() {
        let mut child = Command::new("sleep").arg("30").spawn().unwrap();
        let handle = ProcessHandle::open(child.id() as i32);
        let _ = child.kill();
        child.wait().unwrap();
        // ESRCH is harmless; this handle can never target a later PID reuser.
        handle.unwrap().signal(SIGTERM).unwrap();
    }

    #[test]
    fn rapid_starts_have_distinct_ids_and_do_not_truncate_existing_logs() {
        let ids: std::collections::BTreeSet<_> =
            (0..1000).map(|_| new_id(std::process::id())).collect();
        assert_eq!(ids.len(), 1000);
        assert!(ids.iter().all(|id| crate::catalog::Catalog::valid_id(id)));
        let root = scratch("reserve");
        let path = root.join("existing.ndjson");
        fs::write(&path, b"existing events\n").unwrap();
        assert_eq!(
            private_create_new(&path).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(fs::read(&path).unwrap(), b"existing events\n");
        let _ = fs::remove_dir_all(&root);
    }

    fn scratch(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("rcp-jobs-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    /// `cancel` must not signal a process that is merely REUSING the job's pid.
    ///
    /// A pid is a small integer the kernel hands out again. `cancel` asked
    /// `kill(pid, 0)` -- "is any process numbered `pid` alive" -- and then sent SIGTERM
    /// and SIGKILL to whatever answered. On a busy machine a job that exited without
    /// recording an outcome leaves a record naming a pid that now belongs to something
    /// else, and no attacker is needed to reach that state.
    ///
    /// This process stands in for the reuser: it is alive and has the recorded pid, but a
    /// DIFFERENT start time, which is exactly the shape of a reused pid. `is_job` must say
    /// no, and the control below is the same job with the RIGHT start time, which must say
    /// yes -- without it a fix that refused everything would pass.
    #[test]
    fn a_reused_pid_is_not_the_job_that_recorded_it() {
        let root = std::env::temp_dir().join(format!("rcp-pidreuse-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let jobs = Jobs::at(&root);
        fs::create_dir_all(&jobs.dir).unwrap();
        let me = std::process::id() as i32;
        let real = proc_start(me);
        assert!(
            real.is_some(),
            "/proc is needed for this arm and this check to mean anything"
        );

        let mk = |pid_start: Option<u64>| Job {
            id: "j".into(),
            argv: vec!["copy".into()],
            pid: me,
            pid_start,
            started: 1,
            state: "running".into(),
            catalog: None,
        };
        assert!(
            !jobs.is_job(&mk(Some(real.unwrap() + 1))),
            "a different start time is a different process wearing the same pid"
        );
        assert!(
            jobs.is_job(&mk(real)),
            "the matching start time must still be recognized"
        );
        // a record written before the field existed keeps the old behavior rather than
        // becoming uncancelable
        assert!(
            jobs.is_job(&mk(None)),
            "an older record with no start time must still cancel"
        );
        // and a pid nothing holds is not a job whatever the record says
        assert!(
            !jobs.is_job(&Job {
                pid: -1,
                ..mk(real)
            }),
            "a nonsense pid is not alive"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn a_stale_job_with_a_reused_pid_can_be_forgotten() {
        let root = scratch("stale-status");
        let jobs = Jobs::at(&root);
        let pid = std::process::id() as i32;
        let start = proc_start(pid).expect("/proc is required to verify process identity");
        let job = Job {
            id: "stale".into(),
            argv: vec!["scan".into()],
            pid,
            pid_start: Some(start + 1),
            started: 1,
            state: "running".into(),
            catalog: None,
        };
        fs::create_dir_all(&jobs.dir).unwrap();
        jobs.write(&job).unwrap();
        assert_eq!(jobs.status("stale").unwrap().state, "canceled");
        jobs.forget("stale").unwrap();
        assert!(!jobs.file("stale").unwrap().exists());

        let running = Job {
            id: "current".into(),
            pid_start: Some(start),
            ..job
        };
        jobs.write(&running).unwrap();
        assert_eq!(jobs.status("current").unwrap().state, "running");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_job_record_round_trips_through_its_file() {
        let root = scratch("record");
        let jobs = Jobs::at(&root);
        fs::create_dir_all(&jobs.dir).unwrap();
        let job = Job {
            id: "job-1-2".into(),
            argv: vec![
                "copy".into(),
                "-newid".into(),
                "x".into(),
                "/a b".into(),
                "/c\"d".into(),
            ],
            pid: 1234,
            pid_start: Some(4242),
            started: 99,
            state: "running".into(),
            catalog: Some("x".into()),
        };
        jobs.write(&job).unwrap();
        assert_eq!(jobs.read("job-1-2").unwrap(), job);
        // a path with a space or a quote in it survives, which is why argv is a list
        assert_eq!(jobs.read("job-1-2").unwrap().argv[3], "/a b");
        assert_eq!(jobs.read("job-1-2").unwrap().argv[4], "/c\"d");
        // a job with no catalog reads back as none rather than as an empty name
        let plain = Job {
            id: "job-3-4".into(),
            catalog: None,
            ..job.clone()
        };
        jobs.write(&plain).unwrap();
        assert_eq!(jobs.read("job-3-4").unwrap().catalog, None);
        assert_eq!(jobs.list().unwrap().len(), 2);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn the_log_is_read_forward_and_never_splits_a_line() {
        let root = scratch("log");
        let jobs = Jobs::at(&root);
        fs::create_dir_all(&jobs.dir).unwrap();
        fs::write(
            jobs.events("j").unwrap(),
            "{\"event\":\"entry\"}\n{\"event\":\"done\"",
        )
        .unwrap();
        // the complete line comes back; the partial one waits for the rest
        let (text, at) = jobs.log("j", 0).unwrap();
        assert_eq!(text, "{\"event\":\"entry\"}\n");
        assert_eq!(at, 18);
        let (text, at2) = jobs.log("j", at).unwrap();
        assert_eq!(text, "", "a partial line must not be handed over");
        assert_eq!(at2, at);
        // once it is finished, it is
        fs::write(
            jobs.events("j").unwrap(),
            "{\"event\":\"entry\"}\n{\"event\":\"done\"}\n",
        )
        .unwrap();
        let (text, _) = jobs.log("j", at).unwrap();
        assert_eq!(text, "{\"event\":\"done\"}\n");
        // a job with no events yet reads as nothing, not as an error
        assert_eq!(jobs.log("nothing-here", 0).unwrap(), (String::new(), 0));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn the_state_comes_from_the_events_not_the_file() {
        let root = scratch("state");
        let jobs = Jobs::at(&root);
        fs::create_dir_all(&jobs.dir).unwrap();
        // a file that says running, a pid that is this process (so it is alive), and
        // events that say the run finished: the events win
        let job = Job {
            id: "j".into(),
            argv: vec!["scan".into()],
            pid: std::process::id() as i32,
            pid_start: proc_start(std::process::id() as i32),
            started: 1,
            state: "running".into(),
            catalog: None,
        };
        jobs.write(&job).unwrap();
        fs::write(
            jobs.events("j").unwrap(),
            "{\"event\":\"entry\"}\n{\"event\":\"done\",\"status\":\"failed\"}\n",
        )
        .unwrap();
        assert_eq!(jobs.status("j").unwrap().state, "failed");
        // and the file is updated, so the next reader does not have to re-derive it
        assert_eq!(jobs.read("j").unwrap().state, "failed");
        // a job whose process is gone with no done event was canceled or died
        let gone = Job {
            id: "k".into(),
            pid: 0x7fff_fffe,
            state: "running".into(),
            ..job.clone()
        };
        jobs.write(&gone).unwrap();
        assert_eq!(jobs.status("k").unwrap().state, "canceled");
        // forgetting a finished job removes its three files; a running one is refused
        jobs.forget("j").unwrap();
        assert!(!jobs.file("j").unwrap().exists());
        assert!(!jobs.events("j").unwrap().exists());
        let running = Job {
            id: "m".into(),
            pid: std::process::id() as i32,
            state: "running".into(),
            ..job.clone()
        };
        jobs.write(&running).unwrap();
        assert_eq!(
            jobs.forget("m").unwrap_err().kind(),
            io::ErrorKind::ResourceBusy
        );
        let _ = fs::remove_dir_all(&root);
    }
}
