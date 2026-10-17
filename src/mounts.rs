//! `show`: the mounted filesystems this host can copy to and from. `show HOST` (in
//! `nfs/show.rs`) asks a server over the wire; without a host, `show` answers the local
//! question instead: which exports are mounted, where, and with what
//! options. Read from `/proc/self/mountinfo`, which is complete where `/etc/mtab` is not.

use std::fs;
use std::io;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mount {
    pub target: String,
    pub fstype: String,
    pub source: String,
    pub options: String,
}

const NETWORK_TYPES: &[&str] = &[
    "nfs",
    "nfs4",
    "cifs",
    "smb3",
    "smbfs",
    "ceph",
    "glusterfs",
    "fuse.sshfs",
    "fuse.s3fs",
    "fuse.rclone",
    "lustre",
    "9p",
    "virtiofs",
]; // british-english: ignore-line (filesystem type names)

impl Mount {
    pub fn is_network(&self) -> bool {
        NETWORK_TYPES.contains(&self.fstype.as_str())
    }
}

fn unescape(s: &str) -> String {
    // mountinfo escapes space, tab, newline and backslash as octal. Everything else is
    // raw UTF-8, so the bytes have to be decoded as a string rather than one scalar each.
    let mut bytes = Vec::with_capacity(s.len());
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 4 <= b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 4], 8) {
                bytes.push(v);
                i += 4;
                continue;
            }
        }
        bytes.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

pub fn parse_mountinfo(text: &str) -> Vec<Mount> {
    let mut out = Vec::new();
    for line in text.lines() {
        // fields: id parent major:minor root target opts [optional...] - fstype source superopts
        let Some((left, right)) = line.split_once(" - ") else {
            continue;
        };
        let l: Vec<&str> = left.split(' ').collect();
        let r: Vec<&str> = right.split(' ').collect();
        if l.len() < 6 || r.len() < 2 {
            continue;
        }
        let options = if r.len() >= 3 && !r[2].is_empty() {
            format!("{},{}", l[5], r[2])
        } else {
            l[5].to_string()
        };
        out.push(Mount {
            target: unescape(l[4]),
            fstype: r[0].to_string(),
            source: unescape(r[1]),
            options,
        });
    }
    out.sort_by(|a, b| a.target.cmp(&b.target));
    out
}

pub fn mounts() -> io::Result<Vec<Mount>> {
    Ok(parse_mountinfo(&fs::read_to_string(
        "/proc/self/mountinfo",
    )?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mountinfo_lines_parse_into_target_source_and_network_kind() {
        let text = "36 25 0:32 / /mnt/backup rw,relatime shared:1 - nfs4 192.0.2.10:/backup rw,vers=4.2,rsize=1048576\n\
                    22 1 8:1 / / rw,relatime - ext4 /dev/vda1 rw\n\
                    40 25 0:40 / /mnt/with\\040space rw - cifs //nas/share rw,vers=3.1.1\n\
                    garbage line\n";
        let m = parse_mountinfo(text);
        assert_eq!(m.len(), 3);
        assert_eq!(
            m[0],
            Mount {
                target: "/".into(),
                fstype: "ext4".into(),
                source: "/dev/vda1".into(),
                options: "rw,relatime,rw".into()
            }
        );
        assert_eq!(m[1].target, "/mnt/backup");
        assert_eq!(m[1].source, "192.0.2.10:/backup");
        assert!(m[1].is_network());
        assert!(!m[0].is_network());
        assert_eq!(m[2].target, "/mnt/with space");
        assert!(m[2].is_network());
    }

    #[test]
    #[cfg(unix)]
    fn the_live_table_has_a_root() {
        let m = mounts().unwrap();
        assert!(m.iter().any(|x| x.target == "/"), "{m:?}");
    }
}
