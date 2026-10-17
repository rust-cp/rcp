//! Windows local Tree adapter. Names are resolved through pinned directory handles;
//! reparse points are refused and completed files replace their destination atomically.
use crate::catalog::Kind;
use crate::filter::Filter;
use crate::ports::KernelFileDescriptor;
pub use crate::ports::{
    index, is_all_zero, FileOptions, FileOutcome, Item, Listing, MetaOptions, Refusals, Removed,
    Segment, Sink, Tree, ZEROS,
};
use crate::windows::{self, Root, ATTRIBUTES, DELETE, READ, WRITE};
use std::fs::{File, FileTimes, Metadata};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn unsupported(what: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        format!("Windows local adapter does not support {what}"),
    )
}
fn ns(time: SystemTime) -> i128 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_nanos() as i128,
        Err(e) => -(e.duration().as_nanos() as i128),
    }
}
pub fn mtime_ns_of(meta: &Metadata) -> i128 {
    meta.modified().map(ns).unwrap_or(0)
}
pub fn atime_ns_of(meta: &Metadata) -> i128 {
    meta.accessed().map(ns).unwrap_or(0)
}
pub fn system_time(ns: i128) -> SystemTime {
    let value = ns.unsigned_abs();
    let d = Duration::new(
        (value / 1_000_000_000) as u64,
        (value % 1_000_000_000) as u32,
    );
    if ns < 0 {
        UNIX_EPOCH - d
    } else {
        UNIX_EPOCH + d
    }
}
pub fn open_source(path: &Path) -> io::Result<File> {
    windows::PrivateOptions::new().read(true).open(path)
}
pub fn apply_metadata(
    file: &File,
    _path: &Path,
    item: &Item,
    xattrs: &[(String, Vec<u8>)],
    opts: MetaOptions,
) -> io::Result<Refusals> {
    // POSIX permissions cannot express a Windows DACL. Accept only the adapter's
    // synthesized modes; a request carrying other permission semantics is refused.
    if opts.mode && !matches!(item.mode, 0o644 | 0o444 | 0o755) {
        return Err(unsupported(
            "POSIX permissions; Windows ACLs are not translated",
        ));
    }
    if opts.times {
        let m = system_time(item.mtime_ns);
        let a = if opts.atime {
            system_time(item.atime_ns)
        } else {
            m
        };
        file.set_times(FileTimes::new().set_modified(m).set_accessed(a))?;
    }
    Ok(Refusals {
        owner: opts.owner,
        xattrs: xattrs.iter().map(|a| a.0.clone()).collect(),
    })
}
pub struct LocalTree {
    root: PathBuf,
    held: Mutex<Option<Arc<Root>>>,
}
impl LocalTree {
    pub fn new(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
            held: Mutex::new(None),
        }
    }
    pub fn full(&self, rel: &str) -> PathBuf {
        if rel == "." {
            self.root.clone()
        } else {
            self.root.join(rel)
        }
    }
    fn anchor(&self, create: bool) -> io::Result<Arc<Root>> {
        let mut held = self
            .held
            .lock()
            .map_err(|_| io::Error::other("filesystem anchor lock poisoned"))?;
        if let Some(root) = &*held {
            return Ok(root.clone());
        }
        let root = Arc::new(Root::open(&self.root, create)?);
        *held = Some(root.clone());
        Ok(root)
    }
    fn item(&self, rel: &str) -> io::Result<Item> {
        let root = self.anchor(false)?;
        let file = root.open_entry(rel, 0x0010_0080)?;
        let info = windows::info(&file)?;
        let meta = file.metadata()?;
        let kind = if info.is_dir() { Kind::Dir } else { Kind::File };
        Ok(Item {
            rel: rel.into(),
            kind,
            size: if kind == Kind::File { meta.len() } else { 0 },
            mtime_ns: ns(meta.modified()?),
            atime_ns: ns(meta.accessed()?),
            mode: if kind == Kind::Dir { 0o755 } else { 0o644 },
            uid: 0,
            gid: 0,
            dev: info.volume as u64,
            ino: info.identity(),
            nlink: info.links as u64,
            blocks: windows::allocated(&file)?,
            link_target: None,
        })
    }
    fn walk(
        &self,
        rel: &str,
        depth: usize,
        filter: &Filter,
        max: Option<usize>,
        result: &mut Listing,
    ) -> io::Result<()> {
        if max.is_some_and(|limit| depth >= limit) {
            return Ok(());
        }
        let directory = self.anchor(false)?.open_dir(rel, false)?;
        let mut names = Root::names(&directory)?;
        names.sort();
        // NTFS can expose case-sensitive directories. Refuse ambiguity rather than
        // opening an arbitrarily selected entry through case-insensitive handles.
        for (i, name) in names.iter().enumerate() {
            if names[..i]
                .iter()
                .any(|other| windows::same_name(other, name))
            {
                return Err(unsupported("case-colliding directory entries"));
            }
        }
        for name in names {
            let path = if rel == "." {
                name
            } else {
                format!("{rel}/{name}")
            };
            match self.item(&path) {
                Ok(item) => {
                    let dir = item.kind == Kind::Dir;
                    if !filter.allows(&path, dir) {
                        continue;
                    }
                    if dir || filter.admits(&item, crate::filter::now_ns()) {
                        result.items.push(item);
                    }
                    if dir {
                        if let Err(e) = self.walk(&path, depth + 1, filter, max, result) {
                            result.errors.push(format!("{path}: {e}"));
                        }
                    }
                }
                Err(e) => result.errors.push(format!("{path}: {e}")),
            }
        }
        Ok(())
    }
}
pub struct LocalSink {
    file: Option<File>,
    root: Arc<Root>,
    temporary: String,
    destination: String,
    pos: u64,
    done: bool,
}
impl Drop for LocalSink {
    fn drop(&mut self) {
        self.file.take();
        if !self.done {
            let _ = self.root.delete(&self.temporary, false);
        }
    }
}
impl Sink for LocalSink {
    fn reserve(&mut self, len: u64) -> io::Result<()> {
        self.file.as_ref().unwrap().set_len(len)
    }
    fn write(&mut self, data: &[u8]) -> io::Result<()> {
        self.file.as_mut().unwrap().write_all(data)?;
        self.pos += data.len() as u64;
        Ok(())
    }
    fn hole(&mut self, len: u64) -> io::Result<()> {
        self.pos = self
            .pos
            .checked_add(len)
            .ok_or_else(|| io::Error::other("file length overflow"))?;
        self.file
            .as_mut()
            .unwrap()
            .seek(SeekFrom::Start(self.pos))?;
        Ok(())
    }
    fn finish(
        &mut self,
        item: &Item,
        attrs: &[(String, Vec<u8>)],
        opts: MetaOptions,
        fsync: bool,
    ) -> io::Result<Refusals> {
        let file = self.file.as_ref().unwrap();
        file.set_len(self.pos)?;
        let refusals = apply_metadata(
            file,
            &self.root.path.join(&self.temporary),
            item,
            attrs,
            opts,
        )?;
        // Tree::sync must not depend on directory flushing to flush closed file data.
        file.sync_all()?;
        self.root.rename_file(file, &self.destination)?;
        self.done = true;
        if fsync {
            self.root.flush()?;
        }
        Ok(refusals)
    }
    fn raw_fd(&self) -> Option<KernelFileDescriptor> {
        None
    }
}
impl Tree for LocalTree {
    type Reader = File;
    type Sink = LocalSink;
    fn root(&self) -> &Path {
        &self.root
    }
    fn list(&self, filter: &Filter, max: Option<usize>, _parallel: usize) -> io::Result<Listing> {
        let root = match self.item(".") {
            Ok(root) => root,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Ok(Listing::unseen_root(&self.root))
            }
            Err(e) => return Err(e),
        };
        let mut listing = Listing {
            items: vec![root],
            errors: vec![],
        };
        if let Err(e) = self.walk(".", 0, filter, max, &mut listing) {
            listing.errors.push(e.to_string());
        }
        listing.items.sort_by(|a, b| a.rel.cmp(&b.rel));
        Ok(listing)
    }
    fn stat(&self, rel: &str) -> io::Result<Option<Item>> {
        match self.item(rel) {
            Ok(i) => Ok(Some(i)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }
    fn validate_paths(&self, source: &[Item], destination: &[Item]) -> io::Result<()> {
        for src in source {
            for dst in destination {
                if src.rel != dst.rel && windows::same_name(&src.rel, &dst.rel) {
                    return Err(unsupported("case-only name differences between source and destination; rename explicitly first"));
                }
            }
        }
        Ok(())
    }
    fn open(&self, rel: &str) -> io::Result<File> {
        self.anchor(false)?.open_file(rel, READ, false)
    }
    fn read(
        &self,
        rel: &str,
        buf: &mut [u8],
        sink: &mut dyn FnMut(Segment<'_>) -> io::Result<()>,
    ) -> io::Result<()> {
        let mut file = self.open(rel)?;
        loop {
            let n = file.read(buf)?;
            if n == 0 {
                break;
            }
            if is_all_zero(&buf[..n]) {
                sink(Segment::Hole(n as u64))?;
            } else {
                sink(Segment::Data(&buf[..n]))?;
            }
        }
        Ok(())
    }
    fn create_file(&self, item: &Item) -> io::Result<LocalSink> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = self.anchor(true)?;
        let parent = item
            .rel
            .rsplit_once('/')
            .map(|(p, _)| format!("{p}/"))
            .unwrap_or_default();
        let temporary = format!(
            "{parent}.rcp-stage-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let file = root.open_file(&temporary, READ | WRITE | DELETE, true)?;
        if let Err(e) = windows::make_sparse(&file) {
            drop(file);
            let _ = root.delete(&temporary, false);
            return Err(e);
        }
        Ok(LocalSink {
            file: Some(file),
            root,
            temporary,
            destination: item.rel.clone(),
            pos: 0,
            done: false,
        })
    }
    fn kernel_copy(
        &self,
        _rel: &str,
        _sink: &mut LocalSink,
        _opts: &FileOptions,
    ) -> io::Result<Option<u64>> {
        Ok(None)
    }
    fn mkdir(&self, rel: &str) -> io::Result<()> {
        self.anchor(true)?.open_dir(rel, true).map(|_| ())
    }
    fn symlink(&self, _rel: &str, _target: &Path) -> io::Result<()> {
        Err(unsupported("symlinks or junctions"))
    }
    fn hard_link(&self, existing: &str, rel: &str) -> io::Result<()> {
        let root = self.anchor(false)?;
        let file = root.open_file(existing, READ, false)?;
        root.link_file(&file, rel)
    }
    fn remove(&self, rel: &str, kind: Kind) -> io::Result<Removed> {
        if rel == "." {
            return Err(unsupported("removing the tree root"));
        }
        match self.anchor(false)?.delete(rel, kind == Kind::Dir) {
            Ok(()) => Ok(Removed::Gone),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Removed::Gone),
            Err(e) => Removed::or_refused(e),
        }
    }
    fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        let root = self.anchor(false)?;
        let file = root.open_entry(from, READ | DELETE)?;
        root.rename_file(&file, to)
    }
    fn set_metadata(&self, rel: &str, item: &Item, opts: MetaOptions) -> io::Result<Refusals> {
        let root = self.anchor(false)?;
        let file = root.open_entry(rel, ATTRIBUTES)?;
        apply_metadata(&file, &self.full(rel), item, &[], opts)
    }
    fn xattrs(&self, _rel: &str) -> io::Result<Vec<(String, Vec<u8>)>> {
        Ok(vec![])
    }
    fn set_xattrs(&self, _rel: &str, attrs: &[(String, Vec<u8>)]) -> io::Result<Vec<String>> {
        Ok(attrs.iter().map(|a| a.0.clone()).collect())
    }
    fn restore_atime(&self, item: &Item) -> io::Result<()> {
        let file = self.anchor(false)?.open_entry(&item.rel, ATTRIBUTES)?;
        file.set_times(FileTimes::new().set_accessed(system_time(item.atime_ns)))
    }
    fn sync(&self) -> io::Result<()> {
        self.anchor(false)?.flush()
    }
    fn keeps_modes(&self) -> bool {
        false
    }
    fn keeps_owner(&self) -> bool {
        false
    }
    fn keeps_xattrs(&self) -> bool {
        false
    }
    fn rewrites_metadata_in_place(&self) -> bool {
        false
    }
}
