//! Extended attributes through the libc calls, declared here so the crate stays
//! dependency-free. POSIX ACLs (`system.posix_acl_access`, `system.posix_acl_default`) and
//! NFSv4 ACLs on an NFS mount (`system.nfs4_acl`) are extended attributes, so copying them all
//! is what carries the ACLs across. The `l*` variants never follow symlinks; the `f*` variant
//! works on an open descriptor, which is how a file being written gets its attributes before
//! its final mode lands (an ACL can rewrite the group bits, so it must go first).

use std::ffi::CString;
use std::io;
use std::os::fd::RawFd;
use std::os::raw::{c_char, c_int, c_void};
use std::path::Path;

extern "C" {
    fn llistxattr(path: *const c_char, list: *mut c_char, size: usize) -> isize;
    fn lgetxattr(
        path: *const c_char,
        name: *const c_char,
        value: *mut c_void,
        size: usize,
    ) -> isize;
    fn lsetxattr(
        path: *const c_char,
        name: *const c_char,
        value: *const c_void,
        size: usize,
        flags: c_int,
    ) -> c_int;
    fn fsetxattr(
        fd: c_int,
        name: *const c_char,
        value: *const c_void,
        size: usize,
        flags: c_int,
    ) -> c_int;
}

const ERANGE: i32 = 34;
const ENODATA: i32 = 61;
const ENOTSUP: i32 = 95;
const ENOSYS: i32 = 38;
const EPERM: i32 = 1;

fn cpath(path: &Path) -> io::Result<CString> {
    use std::os::unix::ffi::OsStrExt;
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))
}

fn cname(name: &str) -> io::Result<CString> {
    CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "attribute name contains NUL"))
}

/// Attribute names on `path`, sorted. A filesystem without xattr support answers an empty list.
pub fn list(path: &Path) -> io::Result<Vec<String>> {
    let c = cpath(path)?;
    let mut buf: Vec<u8> = vec![0; 1024];
    loop {
        // SAFETY: the buffer outlives the call and its length is passed alongside it.
        let n = unsafe { llistxattr(c.as_ptr(), buf.as_mut_ptr() as *mut c_char, buf.len()) };
        if n >= 0 {
            buf.truncate(n as usize);
            break;
        }
        let err = io::Error::last_os_error();
        match err.raw_os_error() {
            Some(ERANGE) => buf.resize(buf.len() * 4, 0),
            Some(ENOTSUP) | Some(ENOSYS) => return Ok(Vec::new()),
            _ => return Err(err),
        }
    }
    let mut names: Vec<String> = buf
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect();
    names.sort();
    Ok(names)
}

pub fn get(path: &Path, name: &str) -> io::Result<Vec<u8>> {
    let c = cpath(path)?;
    let n = cname(name)?;
    let mut buf: Vec<u8> = vec![0; 256];
    loop {
        // SAFETY: as above.
        let r = unsafe {
            lgetxattr(
                c.as_ptr(),
                n.as_ptr(),
                buf.as_mut_ptr() as *mut c_void,
                buf.len(),
            )
        };
        if r >= 0 {
            buf.truncate(r as usize);
            return Ok(buf);
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(ERANGE) {
            buf.resize(buf.len() * 4, 0);
        } else {
            return Err(err);
        }
    }
}

pub fn set(path: &Path, name: &str, value: &[u8]) -> io::Result<()> {
    let c = cpath(path)?;
    let n = cname(name)?;
    // SAFETY: all three buffers are live for the duration of the call.
    let r = unsafe {
        lsetxattr(
            c.as_ptr(),
            n.as_ptr(),
            value.as_ptr() as *const c_void,
            value.len(),
            0,
        )
    };
    if r == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub fn set_fd(fd: RawFd, name: &str, value: &[u8]) -> io::Result<()> {
    let n = cname(name)?;
    // SAFETY: the descriptor is owned by the caller's open `File`; the buffers are live.
    let r = unsafe {
        fsetxattr(
            fd,
            n.as_ptr(),
            value.as_ptr() as *const c_void,
            value.len(),
            0,
        )
    };
    if r == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Every attribute with its value, in name order: the unit `verify` compares.
pub fn all(path: &Path) -> io::Result<Vec<(String, Vec<u8>)>> {
    let mut out = Vec::new();
    for name in list(path)? {
        match get(path, &name) {
            Ok(v) => out.push((name, v)),
            Err(e) if e.raw_os_error() == Some(ENODATA) => {} // raced with a removal
            Err(e) => return Err(e),
        }
    }
    Ok(out)
}

/// Whether a failed set is "this caller may not set that attribute here" (reported, not
/// fatal: the bytes and the POSIX metadata still landed) rather than a real I/O failure.
pub fn is_refusal(e: &io::Error) -> bool {
    matches!(e.raw_os_error(), Some(EPERM) | Some(ENOTSUP) | Some(ENOSYS))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_attributes_round_trip_or_are_refused_cleanly() {
        let dir = std::env::temp_dir().join(format!("rcp-xattr-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("f");
        std::fs::write(&file, b"x").unwrap();
        match set(&file, "user.rcp.test", b"value") {
            Ok(()) => {
                assert_eq!(get(&file, "user.rcp.test").unwrap(), b"value");
                assert!(list(&file).unwrap().contains(&"user.rcp.test".to_string()));
                assert_eq!(
                    all(&file).unwrap(),
                    vec![("user.rcp.test".to_string(), b"value".to_vec())]
                );
            }
            Err(e) => {
                assert!(is_refusal(&e), "unexpected xattr failure: {e}");
                assert!(list(&file).unwrap().is_empty());
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
