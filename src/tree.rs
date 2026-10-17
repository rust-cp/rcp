//! The tree port: everything the copy, verify and scan logic needs from a place that holds
//! files, and nothing about how that place is reached. `LocalTree` is the adapter over a
//! mounted path; `nfs::client::NfsTree` and `s3::client::S3Tree` implement the same trait
//! over the wire, and the commands do not change.
//!
//! File content crosses the port as segments, `Data` or `Hole`, so sparseness is a property
//! of the stream rather than a trick inside one copy routine: the local adapter finds holes
//! with `SEEK_DATA`/`SEEK_HOLE` where the filesystem supports it and by zero detection where
//! it does not, and any sink can turn a `Hole` back into one.

use std::fs::{self, File, FileTimes, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
use std::os::fd::{AsRawFd, RawFd};
use std::os::raw::{c_int, c_long};
use std::os::unix::fs::{
    fchown, lchown, symlink, FileExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt,
};
use std::path::{Path, PathBuf};
use std::sync::{Condvar, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::catalog::Kind;
use crate::filter::Filter;
use crate::xattr;

use crate::ports::{hash_zeros, Basis, Digest, Digests};
pub use crate::ports::{
    index, is_all_zero, FileOptions, FileOutcome, Item, Listing, MetaOptions, Refusals, Removed,
    Segment, Sink, Tree, ZEROS,
};

/// Applies attributes, ownership, mode and times to an open file, in the order that makes
/// each stick: an ACL rewrites group bits (so before mode), chown clears setuid (so before
/// mode), and times last because everything else bumps ctime only.
pub fn apply_metadata(
    file: &File,
    path: &Path,
    item: &Item,
    xattrs: &[(String, Vec<u8>)],
    opts: MetaOptions,
) -> io::Result<Refusals> {
    let mut refusals = Refusals::default();
    for (name, value) in xattrs {
        if let Err(e) = xattr::set_fd(file.as_raw_fd(), name, value) {
            if xattr::is_refusal(&e) {
                refusals.xattrs.push(name.clone());
            } else {
                return Err(io::Error::new(
                    e.kind(),
                    format!("setxattr {name} on {}: {e}", path.display()),
                ));
            }
        }
    }
    if opts.owner {
        match fchown(file, Some(item.uid), Some(item.gid)) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => refusals.owner = true,
            Err(e) => {
                return Err(io::Error::new(
                    e.kind(),
                    format!("chown {}:{} on {}: {e}", item.uid, item.gid, path.display()),
                ))
            }
        }
    }
    if opts.mode {
        file.set_permissions(fs::Permissions::from_mode(item.mode))
            .map_err(|e| ctx(e, path))?;
    }
    if opts.times {
        let m = system_time(item.mtime_ns);
        let a = if opts.atime {
            system_time(item.atime_ns)
        } else {
            m
        };
        file.set_times(FileTimes::new().set_accessed(a).set_modified(m))
            .map_err(|e| ctx(e, path))?;
    }
    Ok(refusals)
}

// ---------------------------------------------------------------------------------------------
// The local adapter
// ---------------------------------------------------------------------------------------------

extern "C" {
    fn lseek(fd: c_int, offset: c_long, whence: c_int) -> c_long;
    fn syncfs(fd: c_int) -> c_int;
    fn posix_fadvise(fd: c_int, offset: c_long, len: c_long, advice: c_int) -> c_int;
    fn copy_file_range(
        fd_in: c_int,
        off_in: *mut c_long,
        fd_out: c_int,
        off_out: *mut c_long,
        len: usize,
        flags: u32,
    ) -> isize;
}

use crate::platform::O_NOFOLLOW;

pub(crate) fn libc_o_nofollow() -> i32 {
    O_NOFOLLOW
}

/// Whether an open refused because the last component is a symlink. The kernel answers
/// `ELOOP` for `O_NOFOLLOW`, and `ENOTDIR` when the path ended in a slash.
fn is_symlink_in_the_way(e: &io::Error, path: &Path) -> bool {
    matches!(e.raw_os_error(), Some(40) | Some(20))
        && fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink())
}

const SEEK_DATA: c_int = 3;
const SEEK_HOLE: c_int = 4;
const ENXIO: i32 = 6;
pub const O_NOATIME: c_int = 0o1000000;
const POSIX_FADV_SEQUENTIAL: c_int = 2;
const POSIX_FADV_DONTNEED: c_int = 4;

pub fn mtime_ns_of(meta: &fs::Metadata) -> i128 {
    meta.mtime() as i128 * 1_000_000_000 + meta.mtime_nsec() as i128
}

pub fn atime_ns_of(meta: &fs::Metadata) -> i128 {
    meta.atime() as i128 * 1_000_000_000 + meta.atime_nsec() as i128
}

pub fn system_time(ns: i128) -> SystemTime {
    if ns >= 0 {
        UNIX_EPOCH + Duration::from_nanos(ns as u64)
    } else {
        UNIX_EPOCH - Duration::from_nanos((-ns) as u64)
    }
}

fn ctx(e: io::Error, what: &Path) -> io::Error {
    io::Error::new(e.kind(), format!("{}: {e}", what.display()))
}

/// Opens a source for reading with `O_NOATIME` when the caller may (owner or root), so the
/// read itself does not dirty the source's inode; otherwise without it.
pub fn open_source(path: &Path) -> io::Result<File> {
    match OpenOptions::new()
        .read(true)
        .custom_flags(O_NOATIME)
        .open(path)
    {
        Ok(f) => Ok(f),
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            OpenOptions::new().read(true).open(path)
        }
        Err(e) => Err(e),
    }
}

pub fn advise_sequential(fd: RawFd) {
    // SAFETY: advisory only; a failure changes nothing.
    unsafe { posix_fadvise(fd, 0, 0, POSIX_FADV_SEQUENTIAL) };
}

pub fn advise_dontneed(fd: RawFd) {
    // SAFETY: advisory only.
    unsafe { posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED) };
}

/// The next data extent at or after `pos`: `Some((start, end))`, or `None` past the last data.
/// `Err` means the filesystem does not support `SEEK_DATA` (the caller treats the whole file
/// as data and relies on zero detection).
pub fn next_extent(fd: RawFd, pos: u64, len: u64) -> io::Result<Option<(u64, u64)>> {
    // SAFETY: lseek on a descriptor the caller owns; it only moves the file offset.
    let start = unsafe { lseek(fd, pos as c_long, SEEK_DATA) };
    if start < 0 {
        let e = io::Error::last_os_error();
        return if e.raw_os_error() == Some(ENXIO) {
            Ok(None)
        } else {
            Err(e)
        };
    }
    let start = (start as u64).min(len);
    // SAFETY: as above.
    let end = unsafe { lseek(fd, start as c_long, SEEK_HOLE) };
    let end = if end < 0 { len } else { (end as u64).min(len) };
    Ok(Some((start, end)))
}

pub struct LocalTree {
    root: PathBuf,
}

impl LocalTree {
    pub fn new(root: &Path) -> LocalTree {
        LocalTree {
            root: root.to_path_buf(),
        }
    }

    pub fn full(&self, rel: &str) -> PathBuf {
        if rel == "." {
            self.root.clone()
        } else {
            self.root.join(rel)
        }
    }

    fn item_of(&self, rel: String) -> io::Result<Option<Item>> {
        let full = self.full(&rel);
        let meta = fs::symlink_metadata(&full).map_err(|e| ctx(e, &full))?;
        let ft = meta.file_type();
        let kind = if ft.is_dir() {
            Kind::Dir
        } else if ft.is_file() {
            Kind::File
        } else if ft.is_symlink() {
            Kind::Symlink
        } else {
            let what = if ft.is_socket() {
                "socket"
            } else if ft.is_fifo() {
                "fifo"
            } else if ft.is_block_device() || ft.is_char_device() {
                "device"
            } else {
                "special file"
            };
            eprintln!("WARN: skipping {what} {}", full.display());
            return Ok(None);
        };
        let link_target = if kind == Kind::Symlink {
            Some(fs::read_link(&full).map_err(|e| ctx(e, &full))?)
        } else {
            None
        };
        Ok(Some(Item {
            rel,
            kind,
            size: if kind == Kind::File { meta.len() } else { 0 },
            mtime_ns: mtime_ns_of(&meta),
            atime_ns: atime_ns_of(&meta),
            mode: meta.mode() & 0o7777,
            uid: meta.uid(),
            gid: meta.gid(),
            dev: meta.dev(),
            ino: meta.ino(),
            nlink: meta.nlink(),
            blocks: meta.blocks() * 512,
            link_target,
        }))
    }
}

/// Work-queue state for the parallel walk: directories waiting to be read, and how many are
/// still being read (a worker may not stop while another could still enqueue more).
struct WalkQueue {
    dirs: Vec<(String, usize)>,
    in_flight: usize,
}

pub struct LocalSink {
    file: File,
    path: PathBuf,
    pos: u64,
    /// A patch sink: the old file the copies come from, the digest of everything written so
    /// far, the digest the caller expects, and the path the rebuilt file takes over on
    /// `finish` (the sink writes beside it until then).
    patch: Option<PatchState>,
}

struct PatchState {
    basis: File,
    hasher: Box<dyn Digest>,
    expected: Option<String>,
    final_path: PathBuf,
    done: bool,
}

impl Drop for LocalSink {
    fn drop(&mut self) {
        // a patch that never finished leaves nothing beside the old file
        if let Some(p) = &self.patch {
            if !p.done {
                let _ = fs::remove_file(&self.path);
            }
        }
    }
}

impl Sink for LocalSink {
    fn reserve(&mut self, len: u64) -> io::Result<()> {
        self.file.set_len(len).map_err(|e| ctx(e, &self.path))
    }
    fn write(&mut self, data: &[u8]) -> io::Result<()> {
        self.file
            .write_all_at(data, self.pos)
            .map_err(|e| ctx(e, &self.path))?;
        self.pos += data.len() as u64;
        if let Some(p) = &mut self.patch {
            p.hasher.update(data);
        }
        Ok(())
    }
    fn hole(&mut self, len: u64) -> io::Result<()> {
        self.pos += len;
        if let Some(p) = &mut self.patch {
            hash_zeros(&mut *p.hasher, len);
        }
        Ok(())
    }
    fn finish(
        &mut self,
        item: &Item,
        xattrs: &[(String, Vec<u8>)],
        opts: MetaOptions,
        fsync: bool,
    ) -> io::Result<Refusals> {
        self.file
            .set_len(self.pos)
            .map_err(|e| ctx(e, &self.path))?;
        if let Some(p) = &mut self.patch {
            let hasher = std::mem::replace(&mut p.hasher, Box::new(NoDigest));
            let got = hasher.finish();
            if p.expected.as_deref() != Some(got.as_str()) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "{}: the rebuilt file digests as {got}, not {}; the old file is kept",
                        p.final_path.display(),
                        p.expected.as_deref().unwrap_or("(nothing expected)")
                    ),
                ));
            }
        }
        let refusals = apply_metadata(&self.file, &self.path, item, xattrs, opts)?;
        if fsync {
            self.file.sync_all().map_err(|e| ctx(e, &self.path))?;
        }
        if let Some(p) = &mut self.patch {
            fs::rename(&self.path, &p.final_path).map_err(|e| ctx(e, &p.final_path))?;
            p.done = true;
            if fsync {
                // the rename is a directory change; the file's own sync does not cover it
                if let Some(dir) = p.final_path.parent() {
                    File::open(dir)
                        .and_then(|d| d.sync_all())
                        .map_err(|e| ctx(e, dir))?;
                }
            }
        }
        Ok(refusals)
    }
    fn copy_basis(&mut self, offset: u64, len: u64) -> io::Result<()> {
        let Some(p) = &mut self.patch else {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "not a patch sink",
            ));
        };
        let mut buf = vec![0u8; len.min(1 << 20) as usize];
        let mut done = 0u64;
        while done < len {
            let take = (len - done).min(buf.len() as u64) as usize;
            p.basis
                .read_exact_at(&mut buf[..take], offset + done)
                .map_err(|e| ctx(e, &p.final_path))?;
            self.file
                .write_all_at(&buf[..take], self.pos)
                .map_err(|e| ctx(e, &self.path))?;
            p.hasher.update(&buf[..take]);
            self.pos += take as u64;
            done += take as u64;
        }
        Ok(())
    }
    fn expect(&mut self, digest: &str) -> io::Result<()> {
        match &mut self.patch {
            Some(p) => {
                p.expected = Some(digest.to_string());
                Ok(())
            }
            None => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "not a patch sink",
            )),
        }
    }
    fn raw_fd(&self) -> Option<RawFd> {
        Some(self.file.as_raw_fd())
    }
    fn drop_cache(&self) {
        if let Some(fd) = self.raw_fd() {
            drop_cache(fd);
        }
    }
}

impl Tree for LocalTree {
    type Reader = File;
    type Sink = LocalSink;

    fn root(&self) -> &Path {
        &self.root
    }

    fn list(
        &self,
        filter: &Filter,
        max_depth: Option<usize>,
        parallel: usize,
    ) -> io::Result<Listing> {
        let meta = fs::metadata(&self.root).map_err(|e| ctx(e, &self.root))?;
        if !meta.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} is not a directory", self.root.display()),
            ));
        }
        let Some(root_item) = self.item_of(".".to_string())? else {
            return Ok(Listing::unseen_root(&self.root));
        };
        let queue = Mutex::new(WalkQueue {
            dirs: vec![(".".to_string(), 0)],
            in_flight: 0,
        });
        let wake = Condvar::new();
        let now = crate::filter::now_ns();
        let collected: Mutex<Listing> = Mutex::new(Listing {
            items: vec![root_item],
            errors: Vec::new(),
        });
        let threads = parallel.clamp(1, 64);
        std::thread::scope(|scope| {
            for _ in 0..threads {
                scope.spawn(|| {
                    let mut items: Vec<Item> = Vec::new();
                    let mut errors: Vec<String> = Vec::new();
                    loop {
                        let (rel, depth) = {
                            let mut q = queue.lock().unwrap();
                            loop {
                                if let Some(d) = q.dirs.pop() {
                                    q.in_flight += 1;
                                    break d;
                                }
                                if q.in_flight == 0 {
                                    drop(q);
                                    collected.lock().unwrap().items.append(&mut items);
                                    collected.lock().unwrap().errors.append(&mut errors);
                                    return;
                                }
                                q = wake.wait(q).unwrap();
                            }
                        };
                        let full = self.full(&rel);
                        let mut subdirs: Vec<(String, usize)> = Vec::new();
                        match fs::read_dir(&full) {
                            Ok(rd) => {
                                for entry in rd {
                                    let name = match entry {
                                        Ok(e) => e.file_name().to_string_lossy().into_owned(),
                                        Err(e) => {
                                            errors.push(format!("{}: {e}", full.display()));
                                            continue;
                                        }
                                    };
                                    let child = if rel == "." {
                                        name
                                    } else {
                                        format!("{rel}/{name}")
                                    };
                                    match self.item_of(child) {
                                        Ok(Some(item)) => {
                                            let is_dir = item.kind == Kind::Dir;
                                            if !filter.allows(&item.rel, is_dir) {
                                                continue;
                                            }
                                            if item.kind == Kind::File
                                                && !filter.allows_file(
                                                    item.size,
                                                    item.mtime_ns,
                                                    now,
                                                )
                                            {
                                                continue;
                                            }
                                            if !is_dir
                                                && !filter.allows_owner_kind(
                                                    item.kind, item.uid, item.gid, item.ino,
                                                )
                                            {
                                                continue;
                                            }
                                            if is_dir && max_depth.is_none_or(|d| depth + 1 < d) {
                                                subdirs.push((item.rel.clone(), depth + 1));
                                            }
                                            items.push(item);
                                        }
                                        Ok(None) => {}
                                        Err(e) => errors.push(e.to_string()),
                                    }
                                }
                            }
                            Err(e) => errors.push(format!("{}: {e}", full.display())),
                        }
                        let mut q = queue.lock().unwrap();
                        q.dirs.append(&mut subdirs);
                        q.in_flight -= 1;
                        drop(q);
                        wake.notify_all();
                    }
                });
            }
        });
        let mut listing = collected.into_inner().unwrap();
        listing.items.sort_unstable_by(|a, b| a.rel.cmp(&b.rel));
        listing.errors.sort();
        Ok(listing)
    }

    fn stat(&self, rel: &str) -> io::Result<Option<Item>> {
        match self.item_of(rel.to_string()) {
            Ok(i) => Ok(i),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn open(&self, rel: &str) -> io::Result<File> {
        let full = self.full(rel);
        let f = open_source(&full).map_err(|e| ctx(e, &full))?;
        advise_sequential(f.as_raw_fd());
        Ok(f)
    }

    fn read(
        &self,
        rel: &str,
        buf: &mut [u8],
        sink: &mut dyn FnMut(Segment<'_>) -> io::Result<()>,
    ) -> io::Result<()> {
        let full = self.full(rel);
        let mut f = open_source(&full).map_err(|e| ctx(e, &full))?;
        let fd = f.as_raw_fd();
        advise_sequential(fd);
        let len = f.metadata()?.len();
        let mut pos: u64 = 0;
        // Ask the filesystem where the data is; one that cannot say answers with an error and
        // the whole file is treated as data, where zero detection still finds the holes.
        let mut seek_aware = true;
        while pos < len {
            let (data_start, data_end) = if seek_aware {
                match next_extent(fd, pos, len) {
                    Ok(Some(extent)) => extent,
                    Ok(None) => {
                        sink(Segment::Hole(len - pos))?;
                        break;
                    }
                    Err(_) => {
                        seek_aware = false;
                        (pos, len)
                    }
                }
            } else {
                (pos, len)
            };
            if data_start > pos {
                sink(Segment::Hole(data_start - pos))?;
                pos = data_start;
            }
            f.seek(SeekFrom::Start(pos))?;
            while pos < data_end {
                let want = buf.len().min((data_end - pos) as usize);
                let n = f.read(&mut buf[..want]).map_err(|e| ctx(e, &full))?;
                if n == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        format!("{}: file shrank while being read", full.display()),
                    ));
                }
                let chunk = &buf[..n];
                if is_all_zero(chunk) {
                    sink(Segment::Hole(n as u64))?;
                } else {
                    sink(Segment::Data(chunk))?;
                }
                pos += n as u64;
            }
        }
        Ok(())
    }

    fn create_file(&self, item: &Item) -> io::Result<LocalSink> {
        let path = self.full(&item.rel);
        // `O_NOFOLLOW`, because a destination is not always one this run made. A symlink
        // sitting where a file belongs used to be FOLLOWED: measured, a copy into a tree
        // holding `f.txt -> /elsewhere/target` wrote the source's bytes into
        // /elsewhere/target, outside the tree entirely, and left the link in place. Both
        // halves are wrong -- the write escapes, and the copy does not produce the file
        // the source has. The link is removed and the file made in its place, which is
        // what a copy means. (This closes the last component; a symlinked DIRECTORY on
        // the way is handled in `mkdir`.)
        let opened = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .custom_flags(libc_o_nofollow())
            .open(&path);
        let file = match opened {
            Ok(f) => f,
            Err(e) if is_symlink_in_the_way(&e, &path) => {
                fs::remove_file(&path).map_err(|e| ctx(e, &path))?;
                OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .custom_flags(libc_o_nofollow())
                    .open(&path)
                    .map_err(|e| ctx(e, &path))?
            }
            Err(e) => return Err(ctx(e, &path)),
        };
        Ok(LocalSink {
            file,
            path,
            pos: 0,
            patch: None,
        })
    }

    fn create_patch(
        &self,
        item: &Item,
        basis: &Basis,
        digests: &dyn Digests,
    ) -> io::Result<LocalSink> {
        let final_path = self.full(&item.rel);
        let old = OpenOptions::new()
            .read(true)
            .open(&final_path)
            .map_err(|e| ctx(e, &final_path))?;
        let meta = old.metadata().map_err(|e| ctx(e, &final_path))?;
        let now = Basis {
            size: meta.len(),
            mtime_ns: meta.mtime() as i128 * 1_000_000_000 + meta.mtime_nsec() as i128,
            ino: meta.ino(),
        };
        if !meta.is_file() || now != *basis {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{}: changed since it was signed (size {} -> {}, inode {} -> {})",
                    final_path.display(),
                    basis.size,
                    now.size,
                    basis.ino,
                    now.ino
                ),
            ));
        }
        // the rebuilt file grows beside the old one and takes its name only when finished;
        // created exclusively under a name nobody can predict, so a peer on a shared export
        // with the same pid, or a symlink planted at the name, gets a refusal instead of
        // sharing or redirecting the write
        let name = final_path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let mut attempt = 0u32;
        let (file, path) = loop {
            let path = final_path.with_file_name(format!(
                ".{name}.rcp-patch-{}-{:08x}",
                std::process::id(),
                nonce()
            ));
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
            {
                Ok(f) => break (f, path),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists && attempt < 8 => attempt += 1,
                Err(e) => return Err(ctx(e, &path)),
            }
        };
        Ok(LocalSink {
            file,
            path,
            pos: 0,
            patch: Some(PatchState {
                basis: old,
                hasher: digests.start(),
                expected: None,
                final_path,
                done: false,
            }),
        })
    }

    fn kernel_copy(
        &self,
        rel: &str,
        sink: &mut LocalSink,
        opts: &FileOptions,
    ) -> io::Result<Option<u64>> {
        if opts.hash {
            return Ok(None); // the kernel cannot digest what it copies
        }
        let full = self.full(rel);
        let src = open_source(&full).map_err(|e| ctx(e, &full))?;
        let len = src.metadata()?.len();
        let (fd_in, fd_out) = (src.as_raw_fd(), sink.file.as_raw_fd());
        sink.reserve(len)?;
        let mut pos = 0u64;
        let mut copied = 0u64;
        while pos < len {
            let (start, end) = match next_extent(fd_in, pos, len) {
                Ok(Some(e)) => e,
                Ok(None) => break,
                Err(_) => (pos, len),
            };
            let mut off_in = start as c_long;
            let mut off_out = start as c_long;
            while (off_in as u64) < end {
                let want = (end - off_in as u64).min(1 << 30) as usize;
                // SAFETY: both descriptors are open files owned by this function; the offsets are
                // updated by the kernel in place.
                opts.runtime.throttle.take(want as u64);
                let n =
                    unsafe { copy_file_range(fd_in, &mut off_in, fd_out, &mut off_out, want, 0) };
                if n < 0 {
                    let e = io::Error::last_os_error();
                    // EXDEV (cross-filesystem before 5.3), ENOSYS, EINVAL, EOPNOTSUPP: not here
                    return if copied == 0
                        && matches!(e.raw_os_error(), Some(18) | Some(38) | Some(22) | Some(95))
                    {
                        Ok(None)
                    } else {
                        Err(ctx(e, &full))
                    };
                }
                if n == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        format!("{}: file shrank while being read", full.display()),
                    ));
                }
                copied += n as u64;
            }
            pos = end.max(off_in as u64);
            if pos == start {
                break;
            }
        }
        sink.pos = len;
        Ok(Some(copied))
    }

    fn mkdir(&self, rel: &str) -> io::Result<()> {
        let path = self.full(rel);
        match fs::create_dir(&path) {
            Ok(()) => Ok(()),
            // `path.is_dir()` follows a link, so a symlink to a directory answered yes and
            // the whole subtree was then written THROUGH it: measured, a copy into a tree
            // holding `sub -> /elsewhere` put the source's files in /elsewhere. What is
            // there has to be a directory itself, and a link where the source has a
            // directory is replaced, as a file in the same position is.
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => match fs::symlink_metadata(&path)
            {
                Ok(m) if m.is_dir() => Ok(()),
                Ok(m) if m.file_type().is_symlink() => {
                    fs::remove_file(&path).map_err(|e| ctx(e, &path))?;
                    fs::create_dir(&path).map_err(|e| ctx(e, &path))
                }
                _ => Err(ctx(e, &path)),
            },
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                fs::create_dir_all(&path).map_err(|e| ctx(e, &path))
            }
            Err(e) => Err(ctx(e, &path)),
        }
    }

    fn symlink(&self, rel: &str, target: &Path) -> io::Result<()> {
        let path = self.full(rel);
        if let Ok(m) = fs::symlink_metadata(&path) {
            if m.file_type().is_symlink() && fs::read_link(&path).ok().as_deref() == Some(target) {
                return Ok(());
            }
            if m.is_dir() {
                fs::remove_dir(&path).map_err(|e| ctx(e, &path))?;
            } else {
                fs::remove_file(&path).map_err(|e| ctx(e, &path))?;
            }
        }
        symlink(target, &path).map_err(|e| ctx(e, &path))
    }

    fn hard_link(&self, existing: &str, rel: &str) -> io::Result<()> {
        let path = self.full(rel);
        let want =
            fs::symlink_metadata(self.full(existing)).map_err(|e| ctx(e, &self.full(existing)))?;
        if let Ok(m) = fs::symlink_metadata(&path) {
            if m.ino() == want.ino() && m.dev() == want.dev() {
                return Ok(());
            }
            fs::remove_file(&path).map_err(|e| ctx(e, &path))?;
        }
        fs::hard_link(self.full(existing), &path).map_err(|e| ctx(e, &path))
    }

    fn remove(&self, rel: &str, kind: Kind) -> io::Result<Removed> {
        let path = self.full(rel);
        let r = if kind == Kind::Dir {
            fs::remove_dir(&path)
        } else {
            fs::remove_file(&path)
        };
        match r {
            // `NotFound` is `Gone` rather than `Kept`: the end state the caller asked for
            // holds, and nothing is still sitting there for it to be surprised by later.
            Ok(()) => Ok(Removed::Gone),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Removed::Gone),
            // a directory this user may not write is a refusal by the store, not a fault
            Err(e) => Removed::or_refused(ctx(e, &path)),
        }
    }

    fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        let (a, b) = (self.full(from), self.full(to));
        fs::rename(&a, &b).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("rename {} -> {}: {e}", a.display(), b.display()),
            )
        })
    }

    fn set_metadata(&self, rel: &str, item: &Item, opts: MetaOptions) -> io::Result<Refusals> {
        let path = self.full(rel);
        let mut refusals = Refusals::default();
        if opts.owner {
            match lchown(&path, Some(item.uid), Some(item.gid)) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::PermissionDenied => refusals.owner = true,
                Err(e) => {
                    return Err(io::Error::new(
                        e.kind(),
                        format!("chown {}:{} on {}: {e}", item.uid, item.gid, path.display()),
                    ))
                }
            }
        }
        if item.kind != Kind::Symlink {
            if opts.mode {
                fs::set_permissions(&path, fs::Permissions::from_mode(item.mode))
                    .map_err(|e| ctx(e, &path))?;
            }
            if opts.times {
                let f = File::options()
                    .read(true)
                    .open(&path)
                    .map_err(|e| ctx(e, &path))?;
                let m = system_time(item.mtime_ns);
                let a = if opts.atime {
                    system_time(item.atime_ns)
                } else {
                    m
                };
                f.set_times(FileTimes::new().set_accessed(a).set_modified(m))
                    .map_err(|e| ctx(e, &path))?;
            }
        }
        Ok(refusals)
    }

    fn xattrs(&self, rel: &str) -> io::Result<Vec<(String, Vec<u8>)>> {
        let path = self.full(rel);
        xattr::all(&path).map_err(|e| ctx(e, &path))
    }

    fn set_xattrs(&self, rel: &str, attrs: &[(String, Vec<u8>)]) -> io::Result<Vec<String>> {
        let path = self.full(rel);
        let mut refused = Vec::new();
        for (name, value) in attrs {
            if let Err(e) = xattr::set(&path, name, value) {
                if xattr::is_refusal(&e) {
                    refused.push(name.clone());
                } else {
                    return Err(io::Error::new(
                        e.kind(),
                        format!("setxattr {name} on {}: {e}", path.display()),
                    ));
                }
            }
        }
        Ok(refused)
    }

    fn restore_atime(&self, item: &Item) -> io::Result<()> {
        let path = self.full(&item.rel);
        let f = File::options()
            .read(true)
            .open(&path)
            .map_err(|e| ctx(e, &path))?;
        f.set_times(
            FileTimes::new()
                .set_accessed(system_time(item.atime_ns))
                .set_modified(system_time(item.mtime_ns)),
        )
        .map_err(|e| ctx(e, &path))
    }

    fn sync(&self) -> io::Result<()> {
        let dir = File::open(&self.root).map_err(|e| ctx(e, &self.root))?;
        // SAFETY: syncfs on an open descriptor; it takes no buffers.
        if unsafe { syncfs(dir.as_raw_fd()) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn native_copy(
        &self,
        dst: &Self,
        files: &[&Item],
        next: &std::sync::atomic::AtomicUsize,
        workers: usize,
        opts: &FileOptions,
        done: &mut dyn FnMut(usize, io::Result<FileOutcome>),
    ) -> io::Result<()> {
        crate::uring::copy_files(self, dst, files, next, workers, opts, done)
    }
}

/// Drops a copied file from the page cache once it is written (`-nocache`), so a large backup
/// does not evict the host's working set.
pub fn drop_cache(fd: RawFd) {
    advise_dontneed(fd);
}

/// A number no other process is likely to pick: the per-process random hasher keys, a
/// counter, and the clock, folded together.
fn nonce() -> u32 {
    use std::hash::{BuildHasher, Hasher};
    static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u32(COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed));
    h.write_u128(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    );
    h.finish() as u32
}

/// A digest that takes nothing, standing in for one that was just finished.
struct NoDigest;

impl Digest for NoDigest {
    fn update(&mut self, _data: &[u8]) {}
    fn finish(self: Box<Self>) -> String {
        String::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_patch_refuses_a_basis_that_changed_and_leaves_no_temp_file_behind() {
        let dir = std::env::temp_dir().join(format!("rcp-patch-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("f"), b"old content of the destination file").unwrap();
        let tree = LocalTree::new(&dir);
        let item = tree.stat("f").unwrap().unwrap();
        let basis = Basis {
            size: item.size,
            mtime_ns: item.mtime_ns,
            ino: item.ino,
        };
        let digests = crate::hash::Algorithm::Sha256.digests();
        // the basis as it is: a patch sink opens, writes beside the file, and replaces it
        // only on finish, with the digest checked first
        {
            let mut sink = tree.create_patch(&item, &basis, &*digests).unwrap();
            sink.copy_basis(0, 4).unwrap();
            sink.write(b"NEW").unwrap();
            let mut h = digests.start();
            h.update(b"old NEW");
            sink.expect(&h.finish()).unwrap();
            assert_eq!(
                fs::read(dir.join("f")).unwrap(),
                b"old content of the destination file",
                "untouched until finish"
            );
            sink.finish(&item, &[], MetaOptions::default(), false)
                .unwrap();
        }
        assert_eq!(fs::read(dir.join("f")).unwrap(), b"old NEW");
        // controls: a stale basis is refused; a wrong digest keeps the old file; an
        // unfinished patch leaves nothing beside it
        let err = match tree.create_patch(&item, &basis, &*digests) {
            Ok(_) => panic!("a stale basis was accepted"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("changed since it was signed"),
            "{err}"
        );
        let item = tree.stat("f").unwrap().unwrap();
        let basis = Basis {
            size: item.size,
            mtime_ns: item.mtime_ns,
            ino: item.ino,
        };
        {
            let mut sink = tree.create_patch(&item, &basis, &*digests).unwrap();
            sink.write(b"garbage").unwrap();
            sink.expect("0000").unwrap();
            let err = sink
                .finish(&item, &[], MetaOptions::default(), false)
                .unwrap_err();
            assert!(err.to_string().contains("the old file is kept"), "{err}");
        }
        assert_eq!(fs::read(dir.join("f")).unwrap(), b"old NEW");
        {
            let mut sink = tree.create_patch(&item, &basis, &*digests).unwrap();
            sink.write(b"abandoned").unwrap();
        }
        let leftovers: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(leftovers, vec!["f".to_string()], "{leftovers:?}");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn zero_detection_matches_memcmp() {
        assert!(is_all_zero(&[]));
        assert!(is_all_zero(&[0u8; 3000]));
        let mut v = vec![0u8; 3000];
        v[2999] = 1;
        assert!(!is_all_zero(&v));
        assert!(is_all_zero(&vec![0u8; (1 << 20) + 17]));
    }

    #[test]
    fn parallel_listing_is_sorted_complete_and_reports_unreadable_directories() {
        let dir = std::env::temp_dir().join(format!("rcp-list-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        for i in 0..30 {
            let sub = dir.join(format!("d{i:02}"));
            fs::create_dir_all(sub.join("inner")).unwrap();
            fs::write(sub.join("a.txt"), b"a").unwrap();
            fs::write(sub.join("inner/b.txt"), b"bb").unwrap();
        }
        let tree = LocalTree::new(&dir);
        let one = tree.list(&Filter::default(), None, 1).unwrap();
        let many = tree.list(&Filter::default(), None, 8).unwrap();
        // reading a directory updates its atime (relatime), so that field is masked
        let masked = |l: &Listing| {
            l.items
                .iter()
                .map(|i| Item {
                    atime_ns: 0,
                    ..i.clone()
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(
            masked(&one),
            masked(&many),
            "thread count must not change the listing"
        );
        assert_eq!(one.items.len(), 1 + 30 * 4);
        assert!(one.items.windows(2).all(|w| w[0].rel < w[1].rel), "sorted");
        assert!(one.errors.is_empty());
        // depth limit
        let shallow = tree.list(&Filter::default(), Some(1), 4).unwrap();
        assert_eq!(shallow.items.len(), 1 + 30);
        // an unreadable directory is an error entry, not an abort (non-root only)
        if fs::metadata("/proc/self").map(|m| m.uid()).unwrap_or(0) != 0 {
            fs::set_permissions(dir.join("d05"), fs::Permissions::from_mode(0o000)).unwrap();
            let l = tree.list(&Filter::default(), None, 4).unwrap();
            assert_eq!(l.errors.len(), 1, "{:?}", l.errors);
            assert!(
                l.items.iter().any(|i| i.rel == "d05"),
                "the directory itself is still listed"
            );
            fs::set_permissions(dir.join("d05"), fs::Permissions::from_mode(0o755)).unwrap();
        }
        let _ = fs::remove_dir_all(&dir);
    }
}
