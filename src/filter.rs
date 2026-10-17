//! `-match` / `-exclude` filters plus the size and age predicates. Patterns are globs matched
//! against the path relative to the tree root (`dir/sub/file.txt`, root is `.`): `*` matches
//! within one path component, `**` matches across components, `?` one character, `[abc]` a
//! class. A pattern without a `/` is matched against the last component as well, so
//! `-exclude '*.tmp'` means what people expect.
//!
//! Selection is spelled as options rather than an expression language: globs, `-minsize` /
//! `-maxsize`, and `-newer` / `-older` with an age. Predicates apply to files; directories are never held
//! back by a size or an age, because their children may still match.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::catalog::Kind;

#[derive(Debug, Clone, Default)]
pub struct Filter {
    pub include: Vec<String>,
    pub exclude: Vec<String>,
    /// Files smaller than this are left out.
    pub min_size: Option<u64>,
    /// Files larger than this are left out.
    pub max_size: Option<u64>,
    /// Only files modified within this many nanoseconds of now.
    pub newer_than_ns: Option<i128>,
    /// Only files modified more than this many nanoseconds ago.
    pub older_than_ns: Option<i128>,
    /// Only entries of these kinds (`-type f|d|l`); directories are still walked.
    pub kinds: Option<Vec<Kind>>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    /// Only the entry with this inode number (`-fileid N`).
    pub fileid: Option<u64>,
}

impl Filter {
    pub fn is_empty(&self) -> bool {
        self.include.is_empty() && self.exclude.is_empty() && !self.has_predicates()
    }

    /// Whether a non-directory entry's kind, ownership and inode pass (`-type`, `-uid`,
    /// `-gid`, `-fileid`).
    pub fn allows_owner_kind(&self, kind: Kind, uid: u32, gid: u32, ino: u64) -> bool {
        self.kinds.as_ref().is_none_or(|k| k.contains(&kind))
            && self.uid.is_none_or(|u| u == uid)
            && self.gid.is_none_or(|g| g == gid)
            && self.fileid.is_none_or(|f| f == ino)
    }

    /// Whether a path takes part. Directories are never excluded by an include pattern alone
    /// (their children may match), only by an exclude pattern.
    pub fn allows(&self, rel: &str, is_dir: bool) -> bool {
        if rel == "." {
            return true;
        }
        if self.exclude.iter().any(|p| matches(p, rel)) {
            return false;
        }
        if self.include.is_empty() || is_dir {
            return true;
        }
        self.include.iter().any(|p| matches(p, rel))
    }

    /// Whether a file of this size and modification time takes part (`now_ns` is the clock).
    pub fn allows_file(&self, size: u64, mtime_ns: i128, now_ns: i128) -> bool {
        if self.min_size.is_some_and(|m| size < m) || self.max_size.is_some_and(|m| size > m) {
            return false;
        }
        let age = now_ns - mtime_ns;
        if self.newer_than_ns.is_some_and(|n| age > n)
            || self.older_than_ns.is_some_and(|o| age <= o)
        {
            return false;
        }
        true
    }

    /// The path patterns alone, without the attribute predicates. The destination of a
    /// transfer is listed through this, because the two questions asked of it need different
    /// views: what the run may REMOVE or skip is scoped by the whole filter (`admits` below
    /// is applied afterwards), but what a copy would OVERWRITE is every file at that path,
    /// whatever its size, age or owner. Listed through the whole filter, a destination file
    /// smaller than `-size` would be missing from the plan's view, the source file of that
    /// name would be planned as new, and the confirm rail would neither show the overwrite
    /// nor count the run destructive.
    pub fn paths_only(&self) -> Filter {
        Filter {
            include: self.include.clone(),
            exclude: self.exclude.clone(),
            ..Filter::default()
        }
    }

    /// Whether a listed entry passes the attribute predicates, the way every adapter's `list`
    /// applies them after the path patterns: a directory always does (it is walked for what
    /// is inside), a file takes the size, age, owner and kind tests, a symlink the owner and
    /// kind ones.
    pub fn admits(&self, item: &crate::ports::Item, now_ns: i128) -> bool {
        match item.kind {
            Kind::Dir => true,
            Kind::File => {
                self.allows_file(item.size, item.mtime_ns, now_ns)
                    && self.allows_owner_kind(item.kind, item.uid, item.gid, item.ino)
            }
            Kind::Symlink => self.allows_owner_kind(item.kind, item.uid, item.gid, item.ino),
        }
    }

    pub fn has_predicates(&self) -> bool {
        self.min_size.is_some()
            || self.max_size.is_some()
            || self.newer_than_ns.is_some()
            || self.older_than_ns.is_some()
            || self.kinds.is_some()
            || self.uid.is_some()
            || self.gid.is_some()
            || self.fileid.is_some()
    }
}

/// `f`, `d`, `l` or a comma-separated set, as `-type` takes it.
pub fn parse_kinds(text: &str) -> Result<Vec<Kind>, String> {
    text.split(',')
        .map(|t| match t.trim() {
            "f" | "file" => Ok(Kind::File),
            "d" | "dir" | "directory" => Ok(Kind::Dir),
            "l" | "link" | "symlink" => Ok(Kind::Symlink),
            other => Err(format!(
                "-type {other:?}: use f, d or l (comma-separated for several)"
            )),
        })
        .collect()
}

pub fn now_ns() -> i128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as i128)
        .unwrap_or(0)
}

/// `4096`, `64k`, `1m`, `2g`, `1t` (binary units).
pub fn parse_size(text: &str) -> Result<u64, String> {
    let t = text.trim();
    let (num, mult) = match t.chars().last().map(|c| c.to_ascii_lowercase()) {
        Some('k') => (&t[..t.len() - 1], 1u64 << 10),
        Some('m') => (&t[..t.len() - 1], 1 << 20),
        Some('g') => (&t[..t.len() - 1], 1 << 30),
        Some('t') => (&t[..t.len() - 1], 1 << 40),
        _ => (t, 1),
    };
    let n: u64 = num
        .trim()
        .parse()
        .map_err(|_| format!("{text:?} is not a size (use 4096, 64k, 1m, 2g)"))?;
    n.checked_mul(mult)
        .ok_or_else(|| format!("{text:?} is too large"))
}

/// `30s`, `15m`, `6h`, `7d`, `2w`; a bare number is seconds.
pub fn parse_age_ns(text: &str) -> Result<i128, String> {
    let t = text.trim();
    let (num, mult) = match t.chars().last().map(|c| c.to_ascii_lowercase()) {
        Some('s') => (&t[..t.len() - 1], 1i128),
        Some('m') => (&t[..t.len() - 1], 60),
        Some('h') => (&t[..t.len() - 1], 3600),
        Some('d') => (&t[..t.len() - 1], 86_400),
        Some('w') => (&t[..t.len() - 1], 7 * 86_400),
        _ => (t, 1),
    };
    let n: f64 = num
        .trim()
        .parse()
        .map_err(|_| format!("{text:?} is not an age (use 30s, 15m, 6h, 7d, 2w)"))?;
    if n < 0.0 {
        return Err(format!("{text:?}: an age cannot be negative"));
    }
    Ok((n * mult as f64 * 1e9) as i128)
}

pub fn matches(pattern: &str, rel: &str) -> bool {
    if glob(pattern.as_bytes(), rel.as_bytes()) {
        return true;
    }
    if !pattern.contains('/') {
        if let Some(last) = rel.rsplit('/').next() {
            return glob(pattern.as_bytes(), last.as_bytes());
        }
    }
    false
}

fn glob(p: &[u8], s: &[u8]) -> bool {
    match p.first() {
        None => s.is_empty(),
        Some(b'*') => {
            if p.len() >= 2 && p[1] == b'*' {
                // `**` spans path separators; `**/` may also match nothing
                let rest = &p[2..];
                let rest = rest.strip_prefix(b"/").unwrap_or(rest);
                (0..=s.len()).any(|i| glob(rest, &s[i..]))
            } else {
                (0..=s.len())
                    .take_while(|&i| i == 0 || s[i - 1] != b'/')
                    .any(|i| glob(&p[1..], &s[i..]))
            }
        }
        Some(b'?') => !s.is_empty() && s[0] != b'/' && glob(&p[1..], &s[1..]),
        Some(b'[') => {
            let Some(close) = p.iter().position(|&c| c == b']') else {
                return s.first() == Some(&b'[') && glob(&p[1..], &s[1..]);
            };
            let Some(&c) = s.first() else { return false };
            let (class, negate) = if p.get(1) == Some(&b'!') {
                (&p[2..close], true)
            } else {
                (&p[1..close], false)
            };
            let mut hit = false;
            let mut i = 0;
            while i < class.len() {
                if i + 2 < class.len() && class[i + 1] == b'-' {
                    if class[i] <= c && c <= class[i + 2] {
                        hit = true;
                    }
                    i += 3;
                } else {
                    if class[i] == c {
                        hit = true;
                    }
                    i += 1;
                }
            }
            hit != negate && glob(&p[close + 1..], &s[1..])
        }
        Some(&c) => s.first() == Some(&c) && glob(&p[1..], &s[1..]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn globs_match_stars_double_stars_question_marks_and_character_classes() {
        assert!(matches("*.txt", "a/b/c.txt"));
        assert!(!matches("*.txt", "a/b/c.tmp"));
        assert!(matches("a/*/c.txt", "a/b/c.txt"));
        assert!(!matches("a/*/c.txt", "a/b/d/c.txt"));
        assert!(matches("a/**/c.txt", "a/b/d/c.txt"));
        assert!(matches("a/**/c.txt", "a/c.txt"));
        assert!(matches("**/*.bin", "x/y/z.bin"));
        assert!(matches("f0?.dat", "dir/f01.dat"));
        assert!(matches("[a-c]*", "b.txt"));
        assert!(!matches("[!a-c]*", "b.txt"));
        assert!(matches("dir00[0-4]", "dir003"));
    }

    #[test]
    fn an_include_admits_directories_so_children_can_match_and_an_exclude_wins() {
        let f = Filter {
            include: vec!["*.txt".into()],
            exclude: vec!["tmp/**".into(), "*.bak".into()],
            ..Default::default()
        };
        assert!(f.allows("a.txt", false));
        assert!(!f.allows("a.bin", false));
        assert!(
            f.allows("sub", true),
            "directories pass an include filter so their children can match"
        );
        assert!(!f.allows("tmp/a.txt", false));
        // A disjunction, deliberately, and the one assertion here that cannot be split: an
        // exclude of `tmp/**` may keep `tmp`'s contents out EITHER by pruning the directory
        // or by rejecting each child, and either is correct. What must never happen is both
        // admitting -- so the message prints both halves, since a bare `||` that fires names
        // neither.
        let (dir, child) = (f.allows("tmp", true), f.allows("tmp/x", false));
        assert!(
            !dir || !child,
            "`tmp/**` let tmp's contents through: dir admitted={dir}, child admitted={child}"
        );
        assert!(!f.allows("a.txt.bak", false));
        assert!(Filter::default().allows("anything", false));
    }

    #[test]
    fn size_and_age_predicates() {
        let now = 1_000_000_000_000_000_000i128;
        let day = 86_400_000_000_000i128;
        let f = Filter {
            min_size: Some(10),
            max_size: Some(100),
            newer_than_ns: Some(7 * day),
            ..Default::default()
        };
        assert!(f.allows_file(50, now - day, now));
        assert!(!f.allows_file(5, now - day, now), "too small");
        assert!(!f.allows_file(500, now - day, now), "too large");
        assert!(!f.allows_file(50, now - 8 * day, now), "too old");
        let g = Filter {
            older_than_ns: Some(7 * day),
            ..Default::default()
        };
        assert!(g.allows_file(1, now - 8 * day, now));
        assert!(!g.allows_file(1, now - day, now));
        assert!(Filter::default().allows_file(0, now - 100 * day, now));
    }

    #[test]
    fn sizes_and_ages_parse() {
        assert_eq!(parse_size("4096").unwrap(), 4096);
        assert_eq!(parse_size("64k").unwrap(), 64 << 10);
        assert_eq!(parse_size("1M").unwrap(), 1 << 20);
        assert_eq!(parse_size("2g").unwrap(), 2 << 30);
        assert!(parse_size("lots").is_err());
        assert_eq!(parse_age_ns("30").unwrap(), 30_000_000_000);
        assert_eq!(parse_age_ns("2h").unwrap(), 7_200_000_000_000);
        assert_eq!(parse_age_ns("1w").unwrap(), 604_800_000_000_000);
        assert!(parse_age_ns("-1d").is_err());
        assert!(parse_age_ns("soon").is_err());
    }
}
