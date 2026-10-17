//! `tar://ARCHIVE[!/SUBPATH]`: a tar archive as a tree, read or written.
//!
//! The archive itself is an ordinary local file. Reading lists its members and opens one
//! by seeking to its offset, so a copy out of an archive is random access over a file that
//! was written as a stream. Writing appends one member per file in the order the copy
//! reaches them, which is why a tar destination is a single stream whatever `-parallel`
//! says, and why the end-of-archive marker is written in `Tree::sync` -- a tar is not a
//! tar until those two zero blocks are there, so a destination that has not synced has not
//! received the copy.
//!
//! The format is POSIX ustar with pax extended headers (`x`) where ustar cannot carry a
//! value: a path over 100 bytes that will not split at a `/` into prefix and name, a size
//! over 8 GiB, a link target over 100 bytes, a time with nanoseconds, a uid or gid over
//! 2097151. Reading also accepts GNU's `L` and `K` long-name entries, which is what GNU
//! tar writes by default, and GNU's base-256 numeric fields.
//!
//! What a tar has no room for is refused in the open: it has no rename, no random-access
//! overwrite and no delete, so `isync` and `delete` are refused rather than half-done.
//! Holes ARE carried, as GNU pax 1.0 sparse members: a `GNU.sparse.*` extended header and
//! a decimal extent map at the front of the member's data. `tar --sparse --format=posix`
//! writes the same shape and reads this one. The limit is where the decision is made --
//! the header precedes the bytes and a sparse header needs the whole map, so a file whose
//! first 8 MiB are solid is written flat even if a hole comes later: correct, and larger.
//!
//! READING covers all four encodings GNU tar can write: 1.0, 0.1 (`GNU.sparse.map`),
//! 0.0 (repeated `GNU.sparse.offset`/`numbytes`) and old-GNU (typeflag `S`, the map in the
//! header and its extension blocks). Only 1.0 carries `GNU.sparse.major`, so a reader that
//! gates on it reads 0.0 and 0.1 as ordinary members and returns a DIFFERENT FILE while
//! reporting success -- which this did, briefly, and is the reason all four are named.

pub mod client;

use std::sync::Arc;

use crate::ports::Log;

/// How a tar endpoint behaves, from the CLI's options.
#[derive(Clone)]
pub struct Settings {
    /// Owner and group names to write in the header (`-user` / `-group` style), when the
    /// run has a name for the id.
    pub names: Option<Arc<dyn crate::ports::Names>>,
    pub log: Arc<dyn Log>,
    /// Threads used to compress `.tar.gz` members on write, and to inflate them on read;
    /// 1 keeps both on the calling thread.
    ///
    /// Set from the run's `-parallel` rather than from the machine, so a library type
    /// never spawns threads on a decision the caller did not make.
    pub workers: usize,
    /// `-rsyncable`: cut `.tar.gz` members where the CONTENT says to, so an edit early in
    /// the tree leaves the later members byte-identical and a delta of the archive has
    /// something to match. Costs a fraction of a percent of ratio; see
    /// `deflate::GzipWriter::rsyncable`.
    pub rsyncable: bool,
}

impl std::fmt::Debug for Settings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("tar::Settings")
            .field("names", &self.names.is_some())
            .finish()
    }
}
