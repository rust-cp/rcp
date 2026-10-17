//! Operating-system ABI details shared by the driven adapters.
//!
//! Keep these out of the transfer core: Linux AArch64 overrides the generic
//! fcntl flags for compatibility with AArch32. Using x86-64 values silently
//! drops symlink protection on AArch64.
//!
//! Sources: Linux arch/arm64/include/uapi/asm/fcntl.h and
//! include/uapi/asm-generic/fcntl.h.

// 32-bit ARM uses the same legacy values as AArch64 (O_NOFOLLOW = 1<<15), not the
// asm-generic values x86_64 uses. Selecting those on `arm` follows a destination symlink.
#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
pub const O_NOFOLLOW: i32 = 1 << 15;
#[cfg(not(any(target_arch = "aarch64", target_arch = "arm")))]
pub const O_NOFOLLOW: i32 = 1 << 17;

#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
pub const O_DIRECTORY: i32 = 1 << 14;
#[cfg(not(any(target_arch = "aarch64", target_arch = "arm")))]
pub const O_DIRECTORY: i32 = 1 << 16;

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::fs::{self, OpenOptions};
    use std::os::unix::fs::{symlink, OpenOptionsExt};

    #[test]
    fn protected_opens_refuse_file_and_directory_symlinks() {
        let root = std::env::temp_dir().join(format!(
            "rcp-platform-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        fs::write(root.join("file"), b"untouched").unwrap();
        fs::create_dir(root.join("dir")).unwrap();
        symlink(root.join("file"), root.join("file-link")).unwrap();
        symlink(root.join("dir"), root.join("dir-link")).unwrap();
        assert!(OpenOptions::new()
            .write(true)
            .truncate(true)
            .custom_flags(O_NOFOLLOW)
            .open(root.join("file-link"))
            .is_err());
        assert_eq!(fs::read(root.join("file")).unwrap(), b"untouched");
        assert!(OpenOptions::new()
            .read(true)
            .custom_flags(O_DIRECTORY | O_NOFOLLOW)
            .open(root.join("dir-link"))
            .is_err());
        assert!(OpenOptions::new()
            .read(true)
            .custom_flags(O_DIRECTORY)
            .open(root.join("file"))
            .is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
