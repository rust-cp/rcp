//! An io_uring copy engine, std-only: the ring is set up with raw syscalls and the shared
//! memory is mapped by hand, because the point of this crate is a binary with no dependencies
//! and the point of this module is concurrency without threads.
//!
//! Each worker owns one ring and drives up to `MAX_JOBS` files at once as small state
//! machines: open both ends, read a window of chunks, write each chunk as it lands (or skip
//! it when it is all zeros, which leaves a hole), hash chunks in offset order, then apply
//! metadata and close. A thread with a queue depth of 64 keeps an NFS server or a fast NVMe
//! device busy in a way a thread doing one blocking read then one blocking write cannot.
//!
//! What is not on the ring: `ftruncate`, `fchmod`, `futimens`, `fchown` and `fsetxattr` have
//! no io_uring opcodes on the kernels this targets, so metadata is applied with plain
//! syscalls once a file's data is complete. Kernels older than 5.6, or hosts where
//! `io_uring_setup` is disabled by policy, make `Ring::new` fail and the caller falls back to
//! the thread engine; nothing about the result differs, only the speed.

use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::raw::{c_int, c_long, c_void};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::ffi::OsStringExt;
use std::path::Path;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use crate::tree::{
    self, is_all_zero, FileOptions as Options, FileOutcome as Outcome, Item, LocalTree, Tree,
};

extern "C" {
    fn syscall(num: c_long, ...) -> c_long;
    fn mmap(
        addr: *mut c_void,
        len: usize,
        prot: c_int,
        flags: c_int,
        fd: c_int,
        off: c_long,
    ) -> *mut c_void;
    fn munmap(addr: *mut c_void, len: usize) -> c_int;
    fn close(fd: c_int) -> c_int;
}

// Generic syscall numbers (x86_64 and aarch64 agree on these three).
const SYS_IO_URING_SETUP: c_long = 425;
const SYS_IO_URING_ENTER: c_long = 426;

const IORING_OFF_SQ_RING: c_long = 0;
const IORING_OFF_CQ_RING: c_long = 0x8000000;
const IORING_OFF_SQES: c_long = 0x10000000;
const IORING_FEAT_SINGLE_MMAP: u32 = 1;
const IORING_ENTER_GETEVENTS: u32 = 1;

const PROT_READ: c_int = 1;
const PROT_WRITE: c_int = 2;
const MAP_SHARED: c_int = 1;
const MAP_POPULATE: c_int = 0x8000;

const OP_OPENAT: u8 = 18;
const OP_CLOSE: u8 = 19;
const OP_READ: u8 = 22;
const OP_WRITE: u8 = 23;

const AT_FDCWD: i32 = -100;
const O_RDONLY: u32 = 0;
const O_WRONLY: u32 = 1;
const O_CREAT: u32 = 0o100;
/// A destination is not always a tree this run made. Without `O_NOFOLLOW` a symlink
/// sitting where a file belongs is followed, and the bytes land wherever it points --
/// measured, outside the destination tree entirely. The thread engine does the same; the
/// retry after removing the link is in `done_open_dst`.
const O_NOFOLLOW: u32 = crate::platform::O_NOFOLLOW as u32;
const ELOOP: i32 = 40;
const O_TRUNC: u32 = 0o1000;
const O_CLOEXEC: u32 = 0o2000000;
const EINVAL: i32 = 22;
const EPERM: i32 = 1;

#[repr(C)]
#[derive(Default)]
struct SqOffsets {
    head: u32,
    tail: u32,
    ring_mask: u32,
    ring_entries: u32,
    flags: u32,
    dropped: u32,
    array: u32,
    resv1: u32,
    user_addr: u64,
}

#[repr(C)]
#[derive(Default)]
struct CqOffsets {
    head: u32,
    tail: u32,
    ring_mask: u32,
    ring_entries: u32,
    overflow: u32,
    cqes: u32,
    flags: u32,
    resv1: u32,
    user_addr: u64,
}

#[repr(C)]
#[derive(Default)]
struct Params {
    sq_entries: u32,
    cq_entries: u32,
    flags: u32,
    sq_thread_cpu: u32,
    sq_thread_idle: u32,
    features: u32,
    wq_fd: u32,
    resv: [u32; 3],
    sq_off: SqOffsets,
    cq_off: CqOffsets,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Sqe {
    opcode: u8,
    flags: u8,
    ioprio: u16,
    fd: i32,
    off: u64,
    addr: u64,
    len: u32,
    op_flags: u32,
    user_data: u64,
    buf_index: u16,
    personality: u16,
    splice_fd_in: i32,
    addr3: u64,
    pad: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Cqe {
    user_data: u64,
    res: i32,
    flags: u32,
}

struct Mapping {
    ptr: *mut u8,
    len: usize,
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: the mapping was created by mmap with exactly this length.
        unsafe { munmap(self.ptr as *mut c_void, self.len) };
    }
}

/// One io_uring instance: submission and completion rings plus the SQE array.
pub struct Ring {
    fd: RawFd,
    _sq: Mapping,
    _cq: Option<Mapping>,
    _sqes: Mapping,
    sqes: *mut Sqe,
    sq_tail: *const AtomicU32,
    sq_mask: u32,
    sq_array: *mut u32,
    cq_head: *const AtomicU32,
    cq_tail: *const AtomicU32,
    cq_mask: u32,
    cqes: *const Cqe,
    entries: u32,
    local_tail: u32,
    pending: u32,
    inflight: u32,
}

// SAFETY: a ring is used by exactly one thread; the pointers are into mappings it owns.
unsafe impl Send for Ring {}

impl Drop for Ring {
    fn drop(&mut self) {
        // SAFETY: the descriptor came from io_uring_setup and is closed once.
        unsafe { close(self.fd) };
    }
}

fn map(fd: RawFd, len: usize, off: c_long) -> io::Result<Mapping> {
    // SAFETY: a shared mapping of a ring region the kernel exposes for exactly this purpose.
    let ptr = unsafe {
        mmap(
            std::ptr::null_mut(),
            len,
            PROT_READ | PROT_WRITE,
            MAP_SHARED | MAP_POPULATE,
            fd,
            off,
        )
    };
    if ptr as isize == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(Mapping {
        ptr: ptr as *mut u8,
        len,
    })
}

impl Ring {
    /// Fails with the kernel's reason when io_uring is absent or disabled here.
    pub fn new(entries: u32) -> io::Result<Ring> {
        let mut p = Params::default();
        // SAFETY: io_uring_setup reads and fills a `struct io_uring_params` of this exact layout.
        let fd = unsafe {
            syscall(
                SYS_IO_URING_SETUP,
                entries as c_long,
                &mut p as *mut Params as c_long,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = fd as RawFd;
        let sq_len = p.sq_off.array as usize + p.sq_entries as usize * 4;
        let cq_len = p.cq_off.cqes as usize + p.cq_entries as usize * size_of::<Cqe>();
        let single = p.features & IORING_FEAT_SINGLE_MMAP != 0;
        let sq = match map(
            fd,
            if single { sq_len.max(cq_len) } else { sq_len },
            IORING_OFF_SQ_RING,
        ) {
            Ok(m) => m,
            Err(e) => {
                // SAFETY: closing the descriptor we just received.
                unsafe { close(fd) };
                return Err(e);
            }
        };
        let cq = if single {
            None
        } else {
            Some(map(fd, cq_len, IORING_OFF_CQ_RING)?)
        };
        let sqes = map(
            fd,
            p.sq_entries as usize * size_of::<Sqe>(),
            IORING_OFF_SQES,
        )?;
        let cq_base = cq.as_ref().map_or(sq.ptr, |m| m.ptr);
        // SAFETY: every offset below comes from the kernel for these mappings.
        let ring = unsafe {
            Ring {
                fd,
                sqes: sqes.ptr as *mut Sqe,
                sq_tail: sq.ptr.add(p.sq_off.tail as usize) as *const AtomicU32,
                sq_mask: *(sq.ptr.add(p.sq_off.ring_mask as usize) as *const u32),
                sq_array: sq.ptr.add(p.sq_off.array as usize) as *mut u32,
                cq_head: cq_base.add(p.cq_off.head as usize) as *const AtomicU32,
                cq_tail: cq_base.add(p.cq_off.tail as usize) as *const AtomicU32,
                cq_mask: *(cq_base.add(p.cq_off.ring_mask as usize) as *const u32),
                cqes: cq_base.add(p.cq_off.cqes as usize) as *const Cqe,
                entries: p.sq_entries,
                local_tail: (*(sq.ptr.add(p.sq_off.tail as usize) as *const AtomicU32))
                    .load(Ordering::Relaxed),
                pending: 0,
                inflight: 0,
                _sq: sq,
                _cq: cq,
                _sqes: sqes,
            }
        };
        Ok(ring)
    }

    pub fn capacity_left(&self) -> u32 {
        self.entries.saturating_sub(self.pending + self.inflight)
    }

    pub fn inflight(&self) -> u32 {
        self.inflight + self.pending
    }

    /// Queues one SQE; the caller checked `capacity_left`.
    pub fn push(&mut self, sqe: Sqe) {
        debug_assert!(self.capacity_left() > 0);
        let idx = self.local_tail & self.sq_mask;
        // SAFETY: idx is masked into the SQE array and the index array, both of `entries` slots.
        unsafe {
            *self.sqes.add(idx as usize) = sqe;
            *self.sq_array.add(idx as usize) = idx;
            self.local_tail = self.local_tail.wrapping_add(1);
            (*self.sq_tail).store(self.local_tail, Ordering::Release);
        }
        self.pending += 1;
    }

    /// Submits what is queued and waits for at least `wait_for` completions.
    pub fn submit(&mut self, wait_for: u32) -> io::Result<()> {
        let flags = if wait_for > 0 {
            IORING_ENTER_GETEVENTS
        } else {
            0
        };
        loop {
            // SAFETY: io_uring_enter with no signal mask.
            let r = unsafe {
                syscall(
                    SYS_IO_URING_ENTER,
                    self.fd as c_long,
                    self.pending as c_long,
                    wait_for as c_long,
                    flags as c_long,
                    0 as c_long,
                    0 as c_long,
                )
            };
            if r < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            let submitted = r as u32;
            self.pending -= submitted;
            self.inflight += submitted;
            if self.pending == 0 {
                return Ok(());
            }
        }
    }

    /// Moves every available completion into `out` as `(user_data, res)`.
    pub fn reap(&mut self, out: &mut Vec<(u64, i32)>) {
        // SAFETY: head and tail are the kernel-shared counters; entries between them are ours.
        unsafe {
            let mut head = (*self.cq_head).load(Ordering::Relaxed);
            let tail = (*self.cq_tail).load(Ordering::Acquire);
            while head != tail {
                let cqe = *self.cqes.add((head & self.cq_mask) as usize);
                out.push((cqe.user_data, cqe.res));
                head = head.wrapping_add(1);
                self.inflight -= 1;
            }
            (*self.cq_head).store(head, Ordering::Release);
        }
    }
}

// ---------------------------------------------------------------------------------------------
// SQE builders
// ---------------------------------------------------------------------------------------------

fn sqe_openat(path: &CString, flags: u32, mode: u32, user_data: u64) -> Sqe {
    Sqe {
        opcode: OP_OPENAT,
        fd: AT_FDCWD,
        addr: path.as_ptr() as u64,
        len: mode,
        op_flags: flags,
        user_data,
        ..Default::default()
    }
}

fn sqe_read(fd: RawFd, buf: *mut u8, len: u32, off: u64, user_data: u64) -> Sqe {
    Sqe {
        opcode: OP_READ,
        fd,
        addr: buf as u64,
        len,
        off,
        user_data,
        ..Default::default()
    }
}

fn sqe_write(fd: RawFd, buf: *const u8, len: u32, off: u64, user_data: u64) -> Sqe {
    Sqe {
        opcode: OP_WRITE,
        fd,
        addr: buf as u64,
        len,
        off,
        user_data,
        ..Default::default()
    }
}

fn sqe_close(fd: RawFd, user_data: u64) -> Sqe {
    Sqe {
        opcode: OP_CLOSE,
        fd,
        user_data,
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------------------------
// The copy engine
// ---------------------------------------------------------------------------------------------

const MAX_JOBS: usize = 16;
const READ_WINDOW: usize = 4;
const RING_ENTRIES: u32 = 512;

const TAG_OPEN_SRC: u64 = 1;
const TAG_OPEN_DST: u64 = 2;
const TAG_READ: u64 = 3;
const TAG_WRITE: u64 = 4;
const TAG_CLOSE: u64 = 5;

fn user_data(tag: u64, slot: usize, buf: usize) -> u64 {
    (tag << 56) | ((slot as u64) << 32) | buf as u64
}

fn decode(ud: u64) -> (u64, usize, usize) {
    (
        ud >> 56,
        ((ud >> 32) & 0xff_ffff) as usize,
        (ud & 0xffff_ffff) as usize,
    )
}

struct Buf {
    chunk: usize,
    got: u32,
    written: bool,
    hashed: bool,
}

struct Job<'a> {
    idx: usize,
    item: &'a Item,
    src_path: CString,
    dst_path: CString,
    src_fd: RawFd,
    dst_fd: RawFd,
    opens_pending: u8,
    /// Data chunks as (offset, length), in offset order; holes are the gaps between them.
    chunks: Vec<(u64, u32)>,
    next_submit: usize,
    next_hash: usize,
    cursor: u64,
    reads: usize,
    writes: usize,
    completed: BTreeMap<usize, usize>,
    hasher: Box<dyn crate::ports::Digest>,
    xattrs: Vec<(String, Vec<u8>)>,
    /// Whether a symlink at the destination has already been removed and the open retried,
    /// so one link costs one retry and a race cannot spin.
    relinked: bool,
    error: Option<io::Error>,
}

use crate::ports::hash_zeros;

/// Splits a file into data chunks of at most `bs` bytes using the filesystem's extent map.
fn chunks_of(fd: RawFd, len: u64, bs: usize) -> Vec<(u64, u32)> {
    let mut out = Vec::new();
    let mut pos = 0u64;
    while pos < len {
        let (start, end) = match tree::next_extent(fd, pos, len) {
            Ok(Some(e)) => e,
            Ok(None) => break,
            Err(_) => (pos, len),
        };
        let mut off = start;
        while off < end {
            let n = (end - off).min(bs as u64) as u32;
            out.push((off, n));
            off += n as u64;
        }
        pos = end.max(start + 1);
    }
    out
}

/// Copies the files that `next` hands out from `files`, calling `done` for each. Returns
/// `Err(Unsupported)` before claiming any file when the ring cannot be created or the kernel
/// lacks the opcodes, so the caller can run the same list on the thread engine instead.
pub fn copy_files<'a>(
    src: &LocalTree,
    dst: &LocalTree,
    files: &[&'a Item],
    next: &AtomicUsize,
    workers: usize,
    opts: &Options,
    done: &mut dyn FnMut(usize, io::Result<Outcome>),
) -> io::Result<()> {
    let mut ring = Ring::new(RING_ENTRIES).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Unsupported,
            format!("io_uring unavailable: {e}"),
        )
    })?;
    probe(&mut ring, src.root())?;

    let bs = opts.block_size.max(4096);
    let nbufs = MAX_JOBS * READ_WINDOW / 2;
    let mut pool: Vec<u8> = vec![0u8; nbufs * bs];
    let base = pool.as_mut_ptr();
    let mut free: Vec<usize> = (0..nbufs).rev().collect();
    let mut bufs: Vec<Buf> = (0..nbufs)
        .map(|_| Buf {
            chunk: 0,
            got: 0,
            written: false,
            hashed: false,
        })
        .collect();
    let mut jobs: Vec<Option<Job<'a>>> = (0..MAX_JOBS).map(|_| None).collect();
    let mut active = 0usize;
    let mut cqes: Vec<(u64, i32)> = Vec::with_capacity(RING_ENTRIES as usize);
    let mut exhausted = false;
    // UNDER A RATE LIMIT, ONE FILE IN FLIGHT PER WORKER. `take` sleeps on this thread, and
    // this thread is the whole ring: while it pays for the next read, no completion is
    // reaped, no write is issued and no file is closed. With MAX_JOBS files open it paid
    // for every one of them before finishing any, so 40 files of 200 KB at `-bwlimit 300k`
    // on four workers landed their first file at 10 s and then all at once near 26 s,
    // where the threads engine lands one every 0.7 s. A job's catalog stayed empty that
    // whole time, so a cancel left nothing to resume. Many files in flight hide latency;
    // under a limit the rate is the bound, so there is no latency left to hide.
    let in_flight = if opts.runtime.throttle.limits() {
        1
    } else {
        MAX_JOBS
    };

    loop {
        // Start jobs while there are free slots and files left. A worker takes at most its
        // share of what remains, so three large files on four workers go to three workers
        // (each hashing its own) rather than all landing on the first ring to ask.
        if !exhausted {
            let remaining = files.len().saturating_sub(next.load(Ordering::Relaxed));
            let share = remaining.div_ceil(workers.max(1)).clamp(1, in_flight);
            for slot in 0..MAX_JOBS {
                if jobs[slot].is_some() || ring.capacity_left() < 2 || active >= share {
                    continue;
                }
                let i = next.fetch_add(1, Ordering::Relaxed);
                if i >= files.len() {
                    exhausted = true;
                    break;
                }
                let item = files[i];
                let xattrs = if opts.xattrs {
                    match src.xattrs(&item.rel) {
                        Ok(v) => v,
                        Err(e) => {
                            done(
                                i,
                                Err(io::Error::new(e.kind(), format!("xattr {}: {e}", item.rel))),
                            );
                            continue;
                        }
                    }
                } else {
                    Vec::new()
                };
                let job = Job {
                    idx: i,
                    item,
                    src_path: cstring(&src.full(&item.rel)),
                    dst_path: cstring(&dst.full(&item.rel)),
                    src_fd: -1,
                    dst_fd: -1,
                    opens_pending: 2,
                    chunks: Vec::new(),
                    next_submit: 0,
                    next_hash: 0,
                    cursor: 0,
                    reads: 0,
                    writes: 0,
                    completed: BTreeMap::new(),
                    hasher: opts.runtime.hasher(),
                    xattrs,
                    relinked: false,
                    error: None,
                };
                ring.push(sqe_openat(
                    &job.src_path,
                    O_RDONLY | O_CLOEXEC | tree::O_NOATIME as u32,
                    0,
                    user_data(TAG_OPEN_SRC, slot, 0),
                ));
                ring.push(sqe_openat(
                    &job.dst_path,
                    O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
                    0o600,
                    user_data(TAG_OPEN_DST, slot, 0),
                ));
                jobs[slot] = Some(job);
                active += 1;
            }
        }
        if active == 0 && ring.inflight() == 0 {
            break;
        }
        ring.submit(1)?;
        cqes.clear();
        ring.reap(&mut cqes);

        for &(ud, res) in &cqes {
            let (tag, slot, buf) = decode(ud);
            if tag == TAG_CLOSE {
                continue;
            }
            let Some(job) = jobs[slot].as_mut() else {
                continue;
            };
            match tag {
                TAG_OPEN_SRC | TAG_OPEN_DST => {
                    job.opens_pending -= 1;
                    if res < 0 {
                        // O_NOATIME needs ownership; retry the source open without it once.
                        if tag == TAG_OPEN_SRC
                            && res == -EPERM
                            && job.src_fd == -1
                            && job.error.is_none()
                        {
                            job.opens_pending += 1;
                            ring.push(sqe_openat(
                                &job.src_path,
                                O_RDONLY | O_CLOEXEC,
                                0,
                                user_data(TAG_OPEN_SRC, slot, 0),
                            ));
                            continue;
                        }
                        // ELOOP from O_NOFOLLOW: a symlink is sitting where the file goes.
                        // A copy replaces it with the file the source has rather than
                        // writing through it, which is where the bytes used to end up.
                        if tag == TAG_OPEN_DST
                            && res == -ELOOP
                            && !job.relinked
                            && job.error.is_none()
                        {
                            job.relinked = true;
                            let as_path = std::path::PathBuf::from(std::ffi::OsString::from_vec(
                                job.dst_path.as_bytes().to_vec(),
                            ));
                            if std::fs::remove_file(&as_path).is_ok() {
                                job.opens_pending += 1;
                                ring.push(sqe_openat(
                                    &job.dst_path,
                                    O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
                                    0o600,
                                    user_data(TAG_OPEN_DST, slot, 0),
                                ));
                                continue;
                            }
                        }
                        job.fail(
                            io::Error::from_raw_os_error(-res),
                            if tag == TAG_OPEN_SRC {
                                "open source"
                            } else {
                                "create destination"
                            },
                        );
                    } else if tag == TAG_OPEN_SRC {
                        job.src_fd = res;
                    } else {
                        job.dst_fd = res;
                    }
                    if job.opens_pending == 0 && job.error.is_none() {
                        job.chunks = chunks_of(job.src_fd, job.item.size, bs);
                        tree::advise_sequential(job.src_fd);
                        // SAFETY: a temporary File over a descriptor we own; forgotten, not closed.
                        let f =
                            std::mem::ManuallyDrop::new(unsafe { File::from_raw_fd(job.dst_fd) });
                        if let Err(e) = f.set_len(job.item.size) {
                            job.fail(e, "truncate destination");
                        }
                    }
                }
                TAG_READ => {
                    job.reads -= 1;
                    let b = &mut bufs[buf];
                    let (off, len) = job.chunks[b.chunk];
                    if res < 0 {
                        job.fail(io::Error::from_raw_os_error(-res), "read");
                        free.push(buf);
                    } else if res == 0 {
                        job.fail(
                            io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "file shrank while being read",
                            ),
                            "read",
                        );
                        free.push(buf);
                    } else {
                        b.got += res as u32;
                        if b.got < len && job.error.is_none() {
                            // short read: continue into the same buffer
                            // SAFETY: the buffer slot is `bs` bytes and got < len <= bs.
                            let p = unsafe { base.add(buf * bs + b.got as usize) };
                            opts.runtime.throttle.take((len - b.got) as u64);
                            ring.push(sqe_read(
                                job.src_fd,
                                p,
                                len - b.got,
                                off + b.got as u64,
                                user_data(TAG_READ, slot, buf),
                            ));
                            job.reads += 1;
                            continue;
                        }
                        // SAFETY: the buffer holds `len` bytes read by the kernel.
                        let data =
                            unsafe { std::slice::from_raw_parts(base.add(buf * bs), len as usize) };
                        if job.error.is_none() && !is_all_zero(data) {
                            ring.push(sqe_write(
                                job.dst_fd,
                                data.as_ptr(),
                                len,
                                off,
                                user_data(TAG_WRITE, slot, buf),
                            ));
                            job.writes += 1;
                            b.got = 0; // reused as the write progress counter
                        } else {
                            b.written = true;
                        }
                        job.completed.insert(b.chunk, buf);
                    }
                }
                TAG_WRITE => {
                    let b = &mut bufs[buf];
                    let (off, len) = job.chunks[b.chunk];
                    if res < 0 {
                        job.writes -= 1;
                        job.fail(io::Error::from_raw_os_error(-res), "write");
                        b.written = true;
                    } else {
                        b.got += res as u32;
                        if b.got < len && job.error.is_none() {
                            // SAFETY: as for the short read.
                            let p = unsafe { base.add(buf * bs + b.got as usize) };
                            ring.push(sqe_write(
                                job.dst_fd,
                                p,
                                len - b.got,
                                off + b.got as u64,
                                user_data(TAG_WRITE, slot, buf),
                            ));
                            continue;
                        }
                        job.writes -= 1;
                        b.written = true;
                    }
                    if b.hashed {
                        free.push(buf);
                    }
                }
                _ => {}
            }
        }

        // Service every active job: hash what completed, refill read windows, finish the
        // ones that are done. This runs over all slots, not just the ones that saw a
        // completion, because a job starved of buffers gets them back through another
        // job's write completing.
        for slot in 0..MAX_JOBS {
            let Some(job) = jobs[slot].as_mut() else {
                continue;
            };
            // Hash in offset order whatever has completed, freeing buffers that are also written.
            while let Some(&buf) = job.completed.get(&job.next_hash) {
                let (off, len) = job.chunks[job.next_hash];
                if opts.hash && job.error.is_none() {
                    hash_zeros(&mut *job.hasher, off - job.cursor);
                    // SAFETY: the buffer holds this chunk until it is freed below.
                    let data =
                        unsafe { std::slice::from_raw_parts(base.add(buf * bs), len as usize) };
                    job.hasher.update(data);
                }
                job.cursor = off + len as u64;
                job.completed.remove(&job.next_hash);
                job.next_hash += 1;
                bufs[buf].hashed = true;
                if bufs[buf].written {
                    free.push(buf);
                }
            }

            // Keep the read window full.
            while job.error.is_none()
                && job.opens_pending == 0
                && job.next_submit < job.chunks.len()
                && job.reads < READ_WINDOW
                && ring.capacity_left() > 0
            {
                let Some(buf) = free.pop() else { break };
                let (off, len) = job.chunks[job.next_submit];
                bufs[buf] = Buf {
                    chunk: job.next_submit,
                    got: 0,
                    written: false,
                    hashed: false,
                };
                // SAFETY: slot `buf` of the pool is `bs` bytes, len <= bs.
                let p = unsafe { base.add(buf * bs) };
                opts.runtime.throttle.take(len as u64);
                ring.push(sqe_read(
                    job.src_fd,
                    p,
                    len,
                    off,
                    user_data(TAG_READ, slot, buf),
                ));
                job.next_submit += 1;
                job.reads += 1;
            }

            // Finished, one way or the other?
            let idle = job.reads == 0 && job.writes == 0 && job.opens_pending == 0;
            let complete = job.next_hash == job.chunks.len();
            if idle && (complete || job.error.is_some()) {
                let job = jobs[slot].take().expect("slot is occupied");
                active -= 1;
                let (idx, result) = finish(job, opts, src, &mut ring, slot);
                done(idx, result);
            }
        }
    }
    Ok(())
}

impl Job<'_> {
    fn fail(&mut self, e: io::Error, what: &str) {
        if self.error.is_none() {
            self.error = Some(io::Error::new(
                e.kind(),
                format!("{what} {}: {e}", self.item.rel),
            ));
        }
    }
}

/// Applies metadata, closes descriptors and produces the outcome for a job whose I/O is done.
fn finish(
    mut job: Job<'_>,
    opts: &Options,
    src: &LocalTree,
    ring: &mut Ring,
    slot: usize,
) -> (usize, io::Result<Outcome>) {
    let idx = job.idx;
    let result = (|| {
        if let Some(e) = job.error.take() {
            return Err(e);
        }
        if opts.hash {
            hash_zeros(&mut *job.hasher, job.item.size - job.cursor);
        }
        // SAFETY: we own dst_fd; the File closes it when dropped at the end of this block.
        let file = unsafe { File::from_raw_fd(job.dst_fd) };
        job.dst_fd = -1;
        let dst_path = Path::new(std::ffi::OsStr::from_bytes(job.dst_path.as_bytes()));
        let refusals = tree::apply_metadata(&file, dst_path, job.item, &job.xattrs, opts.meta)?;
        if opts.fsync {
            file.sync_all()?;
        }
        if opts.nocache {
            tree::drop_cache(file.as_raw_fd());
            tree::drop_cache(job.src_fd);
        }
        if opts.preserve_atime {
            if let Err(e) = src.restore_atime(job.item) {
                eprintln!("WARN: atime not restored on {}: {e}", job.item.rel);
            }
        }
        let hasher = std::mem::replace(&mut job.hasher, opts.runtime.hasher());
        Ok(Outcome {
            bytes: job.item.size,
            sha256: if opts.hash {
                Some(hasher.finish())
            } else {
                None
            },
            refusals,
            literal: None,
        })
    })();
    // Close the source on the ring (fire and forget); the destination closed with its File.
    if job.src_fd >= 0 {
        if ring.capacity_left() > 0 {
            ring.push(sqe_close(job.src_fd, user_data(TAG_CLOSE, slot, 0)));
        } else {
            // SAFETY: closing a descriptor we own.
            unsafe { close(job.src_fd) };
        }
    }
    if job.dst_fd >= 0 {
        // SAFETY: as above (only reached on the error path where no File took it).
        unsafe { close(job.dst_fd) };
    }
    (idx, result)
}

fn cstring(path: &Path) -> CString {
    CString::new(path.as_os_str().as_bytes()).expect("paths from the listing contain no NUL")
}

/// Opens and closes the source root through the ring, which proves the four opcodes this
/// engine needs exist on this kernel before any file is claimed.
fn probe(ring: &mut Ring, root: &Path) -> io::Result<()> {
    let path = cstring(root);
    ring.push(sqe_openat(
        &path,
        O_RDONLY | O_CLOEXEC,
        0,
        user_data(TAG_OPEN_SRC, 0, 0),
    ));
    ring.submit(1)?;
    let mut cqes = Vec::new();
    ring.reap(&mut cqes);
    let fd = match cqes.first() {
        Some(&(_, res)) if res >= 0 => res,
        Some(&(_, res)) if res == -EINVAL => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "io_uring lacks IORING_OP_OPENAT (kernel older than 5.6)",
            ))
        }
        Some(&(_, res)) => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "io_uring probe failed: {}",
                    io::Error::from_raw_os_error(-res)
                ),
            ))
        }
        None => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "io_uring probe returned nothing",
            ))
        }
    };
    ring.push(sqe_read(
        fd,
        std::ptr::null_mut(),
        0,
        0,
        user_data(TAG_READ, 0, 0),
    ));
    ring.submit(1)?;
    cqes.clear();
    ring.reap(&mut cqes);
    if let Some(&(_, res)) = cqes.first() {
        if res == -EINVAL {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "io_uring lacks IORING_OP_READ",
            ));
        }
    }
    ring.push(sqe_close(fd, user_data(TAG_CLOSE, 0, 0)));
    ring.submit(1)?;
    cqes.clear();
    ring.reap(&mut cqes);
    Ok(())
}

/// Whether an io_uring ring can be created at all on this host.
pub fn available() -> bool {
    Ring::new(8).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_data_round_trips() {
        for (tag, slot, buf) in [
            (TAG_READ, 0, 0),
            (TAG_WRITE, 15, 31),
            (TAG_CLOSE, 7, 0xffff_ffff),
        ] {
            assert_eq!(decode(user_data(tag, slot, buf)), (tag, slot, buf));
        }
    }

    #[test]
    fn ring_setup_reports_availability_honestly() {
        match Ring::new(8) {
            Ok(mut r) => {
                assert_eq!(r.inflight(), 0);
                assert!(r.capacity_left() >= 8);
                // a NOP-free smoke: close(-1) completes with -EBADF, proving submit and reap work
                r.push(sqe_close(-1, user_data(TAG_CLOSE, 1, 2)));
                r.submit(1).unwrap();
                let mut out = Vec::new();
                r.reap(&mut out);
                assert_eq!(out.len(), 1);
                assert_eq!(decode(out[0].0), (TAG_CLOSE, 1, 2));
                assert_eq!(out[0].1, -9, "EBADF");
                assert_eq!(r.inflight(), 0);
            }
            Err(e) => eprintln!("io_uring unavailable here: {e}"),
        }
    }
}
