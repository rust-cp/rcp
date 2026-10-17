//! User and group names from `/etc/passwd` and `/etc/group`, read once and cached. Listings
//! show names by default (`-nonames` keeps the numbers), and `chown -user`/`-group` accept a
//! name or a number. Reading the files directly keeps the binary free of libc's NSS, which a
//! static binary cannot dlopen anyway; an LDAP or SSSD account that is not in the files shows
//! as its number, which is honest.

use std::collections::BTreeMap;
use std::fs;
use std::sync::OnceLock;

struct Tables {
    users: BTreeMap<u32, String>,
    groups: BTreeMap<u32, String>,
    user_ids: BTreeMap<String, u32>,
    group_ids: BTreeMap<String, u32>,
}

fn parse(text: &str) -> (BTreeMap<u32, String>, BTreeMap<String, u32>) {
    let mut by_id = BTreeMap::new();
    let mut by_name = BTreeMap::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() < 3 || f[0].is_empty() {
            continue;
        }
        if let Ok(id) = f[2].parse::<u32>() {
            by_id.entry(id).or_insert_with(|| f[0].to_string());
            by_name.entry(f[0].to_string()).or_insert(id);
        }
    }
    (by_id, by_name)
}

fn tables() -> &'static Tables {
    static TABLES: OnceLock<Tables> = OnceLock::new();
    TABLES.get_or_init(|| {
        let (users, user_ids) = parse(&fs::read_to_string("/etc/passwd").unwrap_or_default());
        let (groups, group_ids) = parse(&fs::read_to_string("/etc/group").unwrap_or_default());
        Tables {
            users,
            groups,
            user_ids,
            group_ids,
        }
    })
}

/// The user name for `uid`, or the number as text when no file knows it.
pub fn user(uid: u32) -> String {
    tables()
        .users
        .get(&uid)
        .cloned()
        .unwrap_or_else(|| uid.to_string())
}

pub fn group(gid: u32) -> String {
    tables()
        .groups
        .get(&gid)
        .cloned()
        .unwrap_or_else(|| gid.to_string())
}

/// A uid from a number or a user name.
pub fn uid_of(text: &str) -> Option<u32> {
    text.parse::<u32>()
        .ok()
        .or_else(|| tables().user_ids.get(text).copied())
}

pub fn gid_of(text: &str) -> Option<u32> {
    text.parse::<u32>()
        .ok()
        .or_else(|| tables().group_ids.get(text).copied())
}

/// The `Names` port over this host's passwd and group files.
pub struct SystemNames;

impl crate::ports::Names for SystemNames {
    fn user(&self, uid: u32) -> String {
        user(uid)
    }
    fn group(&self, gid: u32) -> String {
        group(gid)
    }
    fn uid_of(&self, name: &str) -> Option<u32> {
        uid_of(name)
    }
    fn gid_of(&self, name: &str) -> Option<u32> {
        gid_of(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_file_format_and_falls_back_to_numbers() {
        let (by_id, by_name) = parse("root:x:0:0:root:/root:/bin/bash\nbin:x:1:1::/bin:/usr/sbin/nologin\nbroken line\n:x:5:5::/:/bin/sh\n");
        assert_eq!(by_id.get(&0).map(String::as_str), Some("root"));
        assert_eq!(by_name.get("bin"), Some(&1));
        assert!(!by_id.contains_key(&5), "an empty name is skipped");
        #[cfg(unix)]
        assert_eq!(user(0), "root", "the live table knows root");
        #[cfg(windows)]
        assert_eq!(
            user(0),
            "0",
            "POSIX IDs are not translated to Windows identities"
        );
        assert_eq!(
            user(4_000_000_000),
            "4000000000",
            "an unknown id prints as a number"
        );
        assert_eq!(uid_of("0"), Some(0));
        #[cfg(unix)]
        assert_eq!(uid_of("root"), Some(0));
        assert_eq!(uid_of("no-such-user-here"), None);
    }
}
