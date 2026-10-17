//! Windows filesystem primitives. Every component is opened relative to the
//! preceding directory handle with reparse processing disabled. Callers never
//! check a path and then trust a second, path-based open.
//!
//! ABI references: Microsoft NtCreateFile, FILE_RENAME_INFORMATION and
//! FILE_DIRECTORY_INFORMATION documentation. Handles are synchronous and owned.

use std::ffi::{c_void, OsStr};
use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::{Component, Path, PathBuf, Prefix};
use std::ptr;

pub const READ: u32 = 0x0012_0089;
pub const WRITE: u32 = 0x0012_0116;
pub const DELETE: u32 = 0x0001_0000;
pub const ATTRIBUTES: u32 = 0x0010_0180;
const DIR_ACCESS: u32 = 0x0010_00a1;
const REPARSE: u32 = 0x400;
const DIRECTORY: u32 = 0x10;
const OPEN: u32 = 1;
const CREATE: u32 = 2;
const OPEN_IF: u32 = 3;

#[link(name = "bcrypt")]
extern "system" {
    fn BCryptGenRandom(provider: *mut c_void, bytes: *mut u8, len: u32, flags: u32) -> i32;
}
/// OS-backed cryptographic entropy. Failure is an error, with no clock fallback.
pub fn random(bytes: &mut [u8]) -> io::Result<()> {
    let len = u32::try_from(bytes.len()).map_err(|_| invalid("random request is too large"))?;
    // SAFETY: writable bounded buffer; BCRYPT_USE_SYSTEM_PREFERRED_RNG accepts a
    // null provider and retains no caller buffer after this synchronous call.
    nt_result(unsafe { BCryptGenRandom(ptr::null_mut(), bytes.as_mut_ptr(), len, 2) })
}

#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}
#[repr(C)]
struct ObjectAttributes {
    length: u32,
    root: *mut c_void,
    name: *mut UnicodeString,
    attributes: u32,
    security_descriptor: *mut c_void,
    security_qos: *mut c_void,
}
#[repr(C)]
#[derive(Default)]
struct IoStatus {
    status: isize,
    information: usize,
}
#[repr(C)]
#[derive(Default)]
pub struct FileInfo {
    pub attributes: u32,
    creation: [u32; 2],
    access: [u32; 2],
    modified: [u32; 2],
    pub volume: u32,
    size_high: u32,
    size_low: u32,
    pub links: u32,
    index_high: u32,
    index_low: u32,
}
impl FileInfo {
    pub fn identity(&self) -> u64 {
        (self.index_high as u64) << 32 | self.index_low as u64
    }
    pub fn is_dir(&self) -> bool {
        self.attributes & DIRECTORY != 0
    }
    pub fn is_reparse(&self) -> bool {
        self.attributes & REPARSE != 0
    }
}

#[link(name = "ntdll")]
extern "system" {
    fn NtCreateFile(
        handle: *mut *mut c_void,
        access: u32,
        object: *mut ObjectAttributes,
        status: *mut IoStatus,
        allocation: *const i64,
        attributes: u32,
        sharing: u32,
        disposition: u32,
        options: u32,
        ea: *const c_void,
        ea_len: u32,
    ) -> i32;
    fn RtlNtStatusToDosError(status: i32) -> u32;
    fn NtSetInformationFile(
        handle: *mut c_void,
        status: *mut IoStatus,
        data: *const c_void,
        length: u32,
        class: u32,
    ) -> i32;
    fn NtQueryDirectoryFile(
        handle: *mut c_void,
        event: *mut c_void,
        apc: *mut c_void,
        context: *mut c_void,
        status: *mut IoStatus,
        buffer: *mut c_void,
        length: u32,
        class: u32,
        single: u8,
        name: *mut UnicodeString,
        restart: u8,
    ) -> i32;
}
#[link(name = "kernel32")]
extern "system" {
    fn CreateFileW(
        name: *const u16,
        access: u32,
        sharing: u32,
        security: *const c_void,
        disposition: u32,
        flags: u32,
        template: *mut c_void,
    ) -> *mut c_void;
    fn GetFileInformationByHandle(file: *mut c_void, info: *mut FileInfo) -> i32;
    fn DeviceIoControl(
        handle: *mut c_void,
        code: u32,
        input: *const c_void,
        input_len: u32,
        output: *mut c_void,
        output_len: u32,
        returned: *mut u32,
        overlapped: *mut c_void,
    ) -> i32;
    fn GetFileInformationByHandleEx(
        file: *mut c_void,
        class: u32,
        info: *mut c_void,
        size: u32,
    ) -> i32;
    fn GetVolumeInformationByHandleW(
        file: *mut c_void,
        volume: *mut u16,
        volume_len: u32,
        serial: *mut u32,
        max_component: *mut u32,
        flags: *mut u32,
        filesystem: *mut u16,
        filesystem_len: u32,
    ) -> i32;
    fn CompareStringOrdinal(
        a: *const u16,
        a_len: i32,
        b: *const u16,
        b_len: i32,
        ignore_case: i32,
    ) -> i32;
    fn GetCurrentProcess() -> *mut c_void;
    fn LocalFree(memory: *mut c_void) -> *mut c_void;
}

#[link(name = "advapi32")]
extern "system" {
    fn OpenProcessToken(process: *mut c_void, access: u32, token: *mut *mut c_void) -> i32;
    fn GetTokenInformation(
        token: *mut c_void,
        class: u32,
        data: *mut c_void,
        length: u32,
        needed: *mut u32,
    ) -> i32;
    fn ConvertSidToStringSidW(sid: *const c_void, text: *mut *mut u16) -> i32;
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        text: *const u16,
        revision: u32,
        descriptor: *mut *mut c_void,
        size: *mut u32,
    ) -> i32;
    #[cfg(test)]
    fn GetSecurityInfo(
        handle: *mut c_void,
        kind: u32,
        requested: u32,
        owner: *mut *mut c_void,
        group: *mut *mut c_void,
        dacl: *mut *mut c_void,
        sacl: *mut *mut c_void,
        descriptor: *mut *mut c_void,
    ) -> u32;
    #[cfg(test)]
    fn GetAclInformation(acl: *const c_void, data: *mut c_void, length: u32, class: u32) -> i32;
    #[cfg(test)]
    fn GetAce(acl: *const c_void, index: u32, ace: *mut *mut c_void) -> i32;
    #[cfg(test)]
    fn EqualSid(a: *const c_void, b: *const c_void) -> i32;
}

struct LocalMemory(*mut c_void);
impl Drop for LocalMemory {
    fn drop(&mut self) {
        // SAFETY: these buffers were allocated by documented LocalAlloc-backed APIs.
        unsafe {
            LocalFree(self.0);
        }
    }
}
struct PrivateDescriptor(LocalMemory);
impl PrivateDescriptor {
    fn new() -> io::Result<Self> {
        let mut token = ptr::null_mut();
        // SAFETY: OpenProcessToken writes one new owned handle and retains no pointer.
        if unsafe { OpenProcessToken(GetCurrentProcess(), 8, &mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: an owned token handle is closeable with CloseHandle, just like File.
        let token = unsafe { File::from_raw_handle(token) };
        let mut needed = 0;
        // SAFETY: the null buffer asks for the required TokenUser size.
        unsafe {
            GetTokenInformation(token.as_raw_handle(), 1, ptr::null_mut(), 0, &mut needed);
        }
        if needed < size_of::<usize>() as u32 || needed > 1 << 20 {
            return Err(io::Error::last_os_error());
        }
        let mut data = vec![0u64; (needed as usize).div_ceil(8)];
        // SAFETY: aligned storage is at least the requested size and lives through use.
        if unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                1,
                data.as_mut_ptr() as *mut c_void,
                needed,
                &mut needed,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: TokenUser starts with SID_AND_ATTRIBUTES, whose first field is a SID pointer.
        let sid = unsafe { *(data.as_ptr() as *const *const c_void) };
        let mut text = ptr::null_mut();
        if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let text_owner = LocalMemory(text as *mut c_void);
        let mut length = 0;
        // SAFETY: the API returns a NUL-terminated SID string owned by text_owner.
        while unsafe { *text.add(length) } != 0 {
            length += 1;
        }
        let sid = String::from_utf16(unsafe { std::slice::from_raw_parts(text, length) })
            .map_err(|_| invalid("the Windows token SID is not Unicode"))?;
        drop(text_owner);
        // Protected, inheritable full control for the creating user only. Existing
        // directories/files keep operator-selected ACLs; this applies only at creation.
        let sddl: Vec<u16> = format!("O:{sid}D:P(A;OICI;FA;;;{sid})")
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let mut descriptor = ptr::null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut descriptor,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(LocalMemory(descriptor)))
    }
}

/// Portable catalog/job open options. ACLs and component safety are applied
/// during the same native create, before any bytes can be exposed to a peer.
#[derive(Default, Clone)]
pub struct PrivateOptions {
    delete: bool,
    read: bool,
    write: bool,
    append: bool,
    create: bool,
    create_new: bool,
    truncate: bool,
}
impl PrivateOptions {
    pub fn delete_access(&mut self, value: bool) -> &mut Self {
        self.delete = value;
        self
    }
    pub fn new() -> Self {
        Self::default()
    }
    pub fn read(&mut self, value: bool) -> &mut Self {
        self.read = value;
        self
    }
    pub fn write(&mut self, value: bool) -> &mut Self {
        self.write = value;
        self
    }
    pub fn append(&mut self, value: bool) -> &mut Self {
        self.append = value;
        self
    }
    pub fn create(&mut self, value: bool) -> &mut Self {
        self.create = value;
        self
    }
    pub fn create_new(&mut self, value: bool) -> &mut Self {
        self.create_new = value;
        self
    }
    pub fn truncate(&mut self, value: bool) -> &mut Self {
        self.truncate = value;
        self
    }
    pub fn open(&self, path: &Path) -> io::Result<File> {
        if !self.read && !self.write && !self.append {
            return Err(invalid("file needs read or write access"));
        }
        if (self.truncate || self.create || self.create_new) && !self.write && !self.append {
            return Err(invalid("creation/truncation needs write access"));
        }
        let parent = Root::open(
            path.parent().ok_or_else(|| invalid("file has no parent"))?,
            false,
        )?;
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| invalid("file has no Unicode name"))?;
        let mut access = 0x0012_0080;
        if self.delete {
            access |= DELETE;
        }
        if self.read {
            access |= 1;
        }
        if self.append {
            access |= 4;
        } else if self.write {
            access |= 2;
        }
        if self.write || self.append {
            access |= 0x100;
        }
        let descriptor = PrivateDescriptor::new()?;
        let file = component_with_descriptor(
            parent.directory(),
            name,
            access,
            if self.create_new {
                CREATE
            } else if self.create {
                OPEN_IF
            } else {
                OPEN
            },
            Some(false),
            Some(&descriptor),
        )?;
        // Never truncate until the exact opened object has passed reparse validation.
        if self.truncate {
            file.set_len(0)?;
        }
        Ok(file)
    }
}

fn nt_result(status: i32) -> io::Result<()> {
    if status >= 0 {
        return Ok(());
    }
    // SAFETY: the conversion accepts any NTSTATUS and returns a Win32 error code.
    Err(io::Error::from_raw_os_error(
        unsafe { RtlNtStatusToDosError(status) } as i32,
    ))
}
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
pub fn validate_name(name: &str) -> io::Result<()> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.ends_with(['.', ' '])
        || name.chars().any(|c| c < ' ' || "\\/:*?\"<>|".contains(c))
    {
        return Err(invalid(
            "not a plain Windows filename (traversal, stream, separator or ambiguous suffix)",
        ));
    }
    let stem = name.split('.').next().unwrap().to_ascii_uppercase();
    if matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) || (stem.len() == 4
        && (stem.starts_with("COM") || stem.starts_with("LPT"))
        && stem.as_bytes()[3].is_ascii_digit())
    {
        return Err(invalid("Windows device names are not tree entries"));
    }
    Ok(())
}
pub fn same_name(a: &str, b: &str) -> bool {
    let a: Vec<u16> = a.encode_utf16().collect();
    let b: Vec<u16> = b.encode_utf16().collect();
    // SAFETY: both buffers are live and lengths are checked by our filename bound.
    unsafe { CompareStringOrdinal(a.as_ptr(), a.len() as i32, b.as_ptr(), b.len() as i32, 1) == 2 }
}
pub fn info(file: &File) -> io::Result<FileInfo> {
    let mut result = FileInfo::default();
    // SAFETY: File owns a live handle and the output has the documented ABI.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut result) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(result)
}
pub fn allocated(file: &File) -> io::Result<u64> {
    #[repr(C)]
    #[derive(Default)]
    struct Standard {
        allocation: i64,
        end: i64,
        links: u32,
        pending: u8,
        directory: u8,
    }
    let mut value = Standard::default();
    // SAFETY: Standard matches FILE_STANDARD_INFO and its full extent is writable.
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            1,
            (&mut value as *mut Standard).cast(),
            size_of::<Standard>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    u64::try_from(value.allocation).map_err(|_| invalid("negative allocation size"))
}
pub fn make_sparse(file: &File) -> io::Result<()> {
    let mut returned = 0u32;
    // SAFETY: synchronous owned handle; FSCTL_SET_SPARSE with null input enables
    // sparseness. No buffers are retained, and the byte count is writable.
    if unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            0x0009_00c4,
            ptr::null(),
            0,
            ptr::null_mut(),
            0,
            &mut returned,
            ptr::null_mut(),
        )
    } == 0
    {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
fn checked(file: File) -> io::Result<File> {
    if info(&file)?.is_reparse() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Windows reparse points (including symlinks and junctions) are refused",
        ));
    }
    Ok(file)
}
fn component(
    parent: &File,
    name: &str,
    access: u32,
    disposition: u32,
    directory: bool,
) -> io::Result<File> {
    component_with_descriptor(parent, name, access, disposition, Some(directory), None)
}
fn component_with_descriptor(
    parent: &File,
    name: &str,
    access: u32,
    disposition: u32,
    directory: Option<bool>,
    descriptor: Option<&PrivateDescriptor>,
) -> io::Result<File> {
    validate_name(name)?;
    let mut wide: Vec<u16> = name.encode_utf16().collect();
    let bytes = wide
        .len()
        .checked_mul(2)
        .filter(|n| *n <= u16::MAX as usize)
        .ok_or_else(|| invalid("Windows filename is too long"))? as u16;
    let mut string = UnicodeString {
        length: bytes,
        maximum_length: bytes,
        buffer: wide.as_mut_ptr(),
    };
    let mut object = ObjectAttributes {
        length: size_of::<ObjectAttributes>() as u32,
        root: parent.as_raw_handle(),
        name: &mut string,
        attributes: 0x40,
        security_descriptor: descriptor.map_or(ptr::null_mut(), |d| d.0 .0),
        security_qos: ptr::null_mut(),
    };
    let mut status = IoStatus::default();
    let mut handle = ptr::null_mut();
    // FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT, and the expected type.
    let options = 0x0020_0020
        | match directory {
            Some(true) => 1,
            Some(false) => 0x40,
            None => 0,
        };
    // SAFETY: all referenced buffers remain live. One validated filename, never a
    // path with intermediate components, is resolved relative to an owned handle.
    nt_result(unsafe {
        NtCreateFile(
            &mut handle,
            access,
            &mut object,
            &mut status,
            ptr::null(),
            0x80,
            3,
            disposition,
            options,
            ptr::null(),
            0,
        )
    })?;
    // SAFETY: a successful create returns a new handle; File closes it exactly once.
    checked(unsafe { File::from_raw_handle(handle) })
}

/// A directory pinned by handles all the way to its volume/share root. Directory
/// enumeration and leaf operations use handles, even if a peer changes reparse metadata.
pub struct Root {
    pub path: PathBuf,
    ancestors: Vec<File>,
}
impl Root {
    pub fn open(path: &Path, create: bool) -> io::Result<Self> {
        Self::open_with_privacy(path, create, false)
    }
    pub fn private_dir(path: &Path) -> io::Result<Self> {
        Self::open_with_privacy(path, true, true)
    }
    fn open_with_privacy(path: &Path, create: bool, private: bool) -> io::Result<Self> {
        let descriptor = if private {
            Some(PrivateDescriptor::new()?)
        } else {
            None
        };
        let absolute = std::path::absolute(path)?;
        let mut parts = absolute.components();
        let prefix = match parts.next() {
            Some(Component::Prefix(p)) => p,
            _ => return Err(invalid("Windows tree needs an absolute drive or UNC path")),
        };
        let base = match prefix.kind() {
            Prefix::Disk(d) | Prefix::VerbatimDisk(d) => format!("\\\\?\\{}:\\", d as char),
            Prefix::UNC(server, share) | Prefix::VerbatimUNC(server, share) => {
                let server = server
                    .to_str()
                    .ok_or_else(|| invalid("UNC server is not Unicode"))?;
                let share = share
                    .to_str()
                    .ok_or_else(|| invalid("UNC share is not Unicode"))?;
                validate_name(server)?;
                validate_name(share)?;
                format!("\\\\?\\UNC\\{server}\\{share}\\")
            }
            _ => {
                return Err(invalid(
                    "Windows device namespaces are not filesystem trees",
                ))
            }
        };
        let wide: Vec<u16> = OsStr::new(&base).encode_wide().chain(Some(0)).collect();
        // SAFETY: the NUL-terminated buffer lives through the call. The volume/share
        // root is opened without reparse processing; subsequent opens are relative.
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                DIR_ACCESS,
                3,
                ptr::null(),
                3,
                0x0220_0000,
                ptr::null_mut(),
            )
        };
        if handle == -1isize as *mut c_void {
            return Err(io::Error::last_os_error());
        }
        let first = checked(unsafe { File::from_raw_handle(handle) })?;
        let mut filesystem = [0u16; 64];
        // SAFETY: the owned root handle and writable filesystem buffer are valid;
        // optional outputs are null. Restrict the adapter to qualified 64-bit NTFS IDs.
        if unsafe {
            GetVolumeInformationByHandleW(
                first.as_raw_handle(),
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                filesystem.as_mut_ptr(),
                filesystem.len() as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let len = filesystem
            .iter()
            .position(|c| *c == 0)
            .unwrap_or(filesystem.len());
        if String::from_utf16_lossy(&filesystem[..len]) != "NTFS" {
            return Err(io::Error::new(io::ErrorKind::Unsupported,
                "Windows local adapter is qualified for NTFS only; other filesystem identities are unsupported"));
        }
        let mut ancestors = vec![first];
        for part in parts {
            match part {
                Component::RootDir => {}
                Component::Normal(name) => {
                    let name = name
                        .to_str()
                        .ok_or_else(|| invalid("Windows path is not Unicode"))?;
                    let file = component_with_descriptor(
                        ancestors.last().unwrap(),
                        name,
                        DIR_ACCESS,
                        if create { OPEN_IF } else { OPEN },
                        Some(true),
                        descriptor.as_ref(),
                    )?;
                    ancestors.push(file);
                }
                _ => return Err(invalid("Windows tree path contains traversal")),
            }
        }
        Ok(Self {
            path: absolute,
            ancestors,
        })
    }
    pub fn directory(&self) -> &File {
        self.ancestors.last().unwrap()
    }
    pub fn open_entry(&self, rel: &str, access: u32) -> io::Result<File> {
        if rel == "." {
            if access == 0x0010_0080 {
                return self.directory().try_clone();
            }
            let name = self
                .path
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or_else(|| invalid("volume root metadata updates are unsupported"))?;
            let parent = self
                .ancestors
                .get(self.ancestors.len().saturating_sub(2))
                .ok_or_else(|| invalid("volume root metadata updates are unsupported"))?;
            return component_with_descriptor(parent, name, access, OPEN, None, None);
        }
        let (dirs, name) = self.parent(rel, false)?;
        component_with_descriptor(
            dirs.last().unwrap_or_else(|| self.directory()),
            &name,
            access,
            OPEN,
            None,
            None,
        )
    }
    pub fn flush(&self) -> io::Result<()> {
        self.open_entry(".", DIR_ACCESS | 6)?.sync_all()
    }
    pub fn parent(&self, rel: &str, create: bool) -> io::Result<(Vec<File>, String)> {
        let mut names: Vec<&str> = rel.split('/').collect();
        let last = names.pop().ok_or_else(|| invalid("no leaf filename"))?;
        validate_name(last)?;
        let mut dirs = Vec::new();
        for name in names {
            let parent = dirs.last().unwrap_or_else(|| self.directory());
            dirs.push(component(
                parent,
                name,
                DIR_ACCESS,
                if create { OPEN_IF } else { OPEN },
                true,
            )?);
        }
        Ok((dirs, last.to_owned()))
    }
    pub fn open_file(&self, rel: &str, access: u32, create_new: bool) -> io::Result<File> {
        let (dirs, name) = self.parent(rel, create_new)?;
        component(
            dirs.last().unwrap_or_else(|| self.directory()),
            &name,
            access,
            if create_new { CREATE } else { OPEN },
            false,
        )
    }
    pub fn open_dir(&self, rel: &str, create: bool) -> io::Result<File> {
        if rel == "." {
            return self.directory().try_clone();
        }
        let (dirs, name) = self.parent(rel, create)?;
        component(
            dirs.last().unwrap_or_else(|| self.directory()),
            &name,
            DIR_ACCESS,
            if create { OPEN_IF } else { OPEN },
            true,
        )
    }
    pub fn delete(&self, rel: &str, directory: bool) -> io::Result<()> {
        let (dirs, name) = self.parent(rel, false)?;
        let file = component(
            dirs.last().unwrap_or_else(|| self.directory()),
            &name,
            DELETE | 0x0010_0080,
            OPEN,
            directory,
        )?;
        let mut status = IoStatus::default();
        let delete = 1u8;
        // SAFETY: FileDispositionInformation has one BOOLEAN; the live owned handle
        // names the exact non-reparse entry, so no path can redirect the deletion.
        nt_result(unsafe {
            NtSetInformationFile(
                file.as_raw_handle(),
                &mut status,
                &delete as *const u8 as *const c_void,
                1,
                13,
            )
        })
    }
    /// Recursively removes checked entries while their directory is pinned. A
    /// reparse point anywhere in the traversal is an error, never followed.
    pub fn remove_tree(&self, rel: &str) -> io::Result<()> {
        if rel == "." {
            return Err(invalid("cannot remove a pinned root"));
        }
        let entry = self.open_entry(rel, 0x0010_0080)?;
        let directory = info(&entry)?.is_dir();
        if directory {
            let held = self.open_dir(rel, false)?;
            for name in Self::names(&held)? {
                self.remove_tree(&format!("{rel}/{name}"))?;
            }
            drop(held);
        }
        drop(entry);
        self.delete(rel, directory)
    }
    pub fn rename_file(&self, file: &File, rel: &str) -> io::Result<()> {
        self.name_file(file, rel, 10)
    }
    pub fn link_file(&self, file: &File, rel: &str) -> io::Result<()> {
        self.name_file(file, rel, 11)
    }
    fn name_file(&self, file: &File, rel: &str, class: u32) -> io::Result<()> {
        let (dirs, name) = self.parent(rel, false)?;
        let parent = dirs.last().unwrap_or_else(|| self.directory());
        let wide: Vec<u16> = name.encode_utf16().collect();
        #[repr(C)]
        struct Rename {
            replace: u32,
            root: *mut c_void,
            length: u32,
            name: [u16; 1],
        }
        let start = std::mem::offset_of!(Rename, name);
        let length = (start + wide.len() * 2).max(size_of::<Rename>());
        let mut buffer = vec![0u64; length.div_ceil(8)];
        let header = buffer.as_mut_ptr() as *mut Rename;
        // SAFETY: storage is aligned, sized for header and UTF-16 tail, and lives
        // through the synchronous call. The destination is one name at a pinned parent.
        unsafe {
            (*header).replace = 1;
            (*header).root = parent.as_raw_handle();
            (*header).length = (wide.len() * 2) as u32;
            ptr::copy_nonoverlapping(
                wide.as_ptr(),
                (header as *mut u8).add(start) as *mut u16,
                wide.len(),
            );
            let mut status = IoStatus::default();
            nt_result(NtSetInformationFile(
                file.as_raw_handle(),
                &mut status,
                header as *const c_void,
                length as u32,
                class,
            ))
        }
    }
    pub fn names(directory: &File) -> io::Result<Vec<String>> {
        let mut buffer = vec![0u64; 8192];
        let mut result = Vec::new();
        let mut restart = 1;
        loop {
            let mut status = IoStatus::default();
            // SAFETY: aligned live storage, synchronous directory handle, no APC.
            let code = unsafe {
                NtQueryDirectoryFile(
                    directory.as_raw_handle(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    &mut status,
                    buffer.as_mut_ptr() as *mut c_void,
                    (buffer.len() * 8) as u32,
                    1,
                    0,
                    ptr::null_mut(),
                    restart,
                )
            };
            if code as u32 == 0x8000_0006 {
                return Ok(result);
            }
            nt_result(code)?;
            restart = 0;
            if status.information == 0 || status.information > buffer.len() * 8 {
                return Err(invalid("invalid Windows directory response size"));
            }
            // SAFETY: the kernel reported the initialized byte extent, bounded above.
            let bytes = unsafe {
                std::slice::from_raw_parts(buffer.as_ptr() as *const u8, status.information)
            };
            let mut offset = 0;
            loop {
                let record = bytes
                    .get(offset..)
                    .filter(|r| r.len() >= 64)
                    .ok_or_else(|| invalid("truncated Windows directory record"))?;
                let next = u32::from_le_bytes(record[..4].try_into().unwrap()) as usize;
                let len = u32::from_le_bytes(record[60..64].try_into().unwrap()) as usize;
                let name = record
                    .get(64..64 + len)
                    .filter(|_| len % 2 == 0)
                    .ok_or_else(|| invalid("invalid Windows directory filename extent"))?;
                let wide: Vec<u16> = name
                    .chunks_exact(2)
                    .map(|b| u16::from_le_bytes([b[0], b[1]]))
                    .collect();
                let name = String::from_utf16(&wide)
                    .map_err(|_| invalid("filename is not valid Unicode"))?;
                if name != "." && name != ".." {
                    validate_name(&name)?;
                    result.push(name);
                }
                if next == 0 {
                    break;
                }
                if next < 64 + len || next % 8 != 0 {
                    return Err(invalid("invalid Windows directory chain"));
                }
                offset = offset
                    .checked_add(next)
                    .filter(|n| *n < bytes.len())
                    .ok_or_else(|| invalid("Windows directory chain overruns its response"))?;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    fn fixture() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "rcp-win-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&path).unwrap();
        path
    }
    #[test]
    fn relative_handles_create_read_list_rename_and_delete_unicode_files() {
        let path = fixture();
        {
            let root = Root::open(&path, false).unwrap();
            root.open_dir("nested", true).unwrap();
            let mut file = root
                .open_file("nested/naïve.txt", READ | WRITE | DELETE, true)
                .unwrap();
            file.write_all(b"content").unwrap();
            file.sync_all().unwrap();
            let id = info(&file).unwrap().identity();
            assert_ne!(id, 0);
            root.rename_file(&file, "nested/renamed.txt").unwrap();
            drop(file);
            assert_eq!(
                Root::names(&root.open_dir("nested", false).unwrap()).unwrap(),
                ["renamed.txt"]
            );
            let mut read = root.open_file("nested/renamed.txt", READ, false).unwrap();
            let mut content = String::new();
            read.read_to_string(&mut content).unwrap();
            assert_eq!(content, "content");
            assert_eq!(info(&read).unwrap().identity(), id);
            drop(read);
            root.delete("nested/renamed.txt", false).unwrap();
            root.delete("nested", true).unwrap();
        }
        std::fs::remove_dir(path).unwrap();
    }
    #[test]
    fn traversal_stream_and_device_names_are_refused() {
        for name in [
            "..",
            ".",
            "../outside",
            "x\\y",
            "x:y",
            "CON",
            "nul.txt",
            "LPT1",
            "x.",
            "x ",
        ] {
            assert!(validate_name(name).is_err(), "{name}");
        }
        assert!(same_name("File", "file"));
        assert!(same_name("Ä", "ä"));
    }
    #[test]
    fn private_files_are_created_with_one_owner_only_allow_ace_and_append_atomically() {
        let path = fixture();
        {
            let private = path.join("catalog");
            let root = Root::private_dir(&private).unwrap();
            let file_path = private.join("index.tsv");
            let mut file = PrivateOptions::new()
                .append(true)
                .create_new(true)
                .open(&file_path)
                .unwrap();
            file.write_all(b"first\n").unwrap();
            let mut descriptor = ptr::null_mut();
            let mut owner = ptr::null_mut();
            let mut dacl = ptr::null_mut();
            // SAFETY: GetSecurityInfo returns pointers into the owned descriptor.
            assert_eq!(
                unsafe {
                    GetSecurityInfo(
                        file.as_raw_handle(),
                        1,
                        5,
                        &mut owner,
                        ptr::null_mut(),
                        &mut dacl,
                        ptr::null_mut(),
                        &mut descriptor,
                    )
                },
                0
            );
            let descriptor = LocalMemory(descriptor);
            assert!(!dacl.is_null());
            let mut sizes = [0u32; 3];
            assert_ne!(
                unsafe { GetAclInformation(dacl, sizes.as_mut_ptr() as *mut c_void, 12, 2) },
                0
            );
            assert_eq!(
                sizes[0], 1,
                "a private file grants access to exactly one principal"
            );
            let mut ace = ptr::null_mut();
            assert_ne!(unsafe { GetAce(dacl, 0, &mut ace) }, 0);
            assert_eq!(unsafe { *(ace as *const u8) }, 0, "an access-allowed ACE");
            assert_ne!(
                unsafe { EqualSid(owner, (ace as *const u8).add(8) as *const c_void) },
                0
            );
            drop(descriptor);
            drop(file);
            PrivateOptions::new()
                .append(true)
                .open(&file_path)
                .unwrap()
                .write_all(b"second\n")
                .unwrap();
            assert_eq!(std::fs::read(&file_path).unwrap(), b"first\nsecond\n");
            root.flush().unwrap();
        }
        std::fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn junctions_are_refused_before_read_or_write() {
        let path = fixture();
        let target = path.join("target");
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("file"), b"untouched").unwrap();
        let link = path.join("junction");
        let result = std::process::Command::new("cmd.exe")
            .args(["/d", "/c", "mklink", "/J"])
            .arg(&link)
            .arg(&target)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        {
            let root = Root::open(&path, false).unwrap();
            assert!(root.open_dir("junction", false).is_err());
            assert!(root.open_file("junction/file", WRITE, false).is_err());
            assert!(root.open_file("junction/new", WRITE, true).is_err());
            assert!(Root::open(&link, false).is_err());
        }
        assert_eq!(std::fs::read(target.join("file")).unwrap(), b"untouched");
        assert!(!target.join("new").exists());
        std::fs::remove_dir(&link).unwrap();
        std::fs::remove_dir_all(path).unwrap();
    }
}
