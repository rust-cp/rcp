//! Kerberos through the system's GSSAPI library (MIT `libgssapi_krb5`, or Heimdal's
//! `libgssapi`), loaded at run time with `dlopen`. That is the same library the kernel's
//! `rpc.gssd`, `mount.nfs`, `curl` and every Hadoop client use, so it reads the host's
//! `krb5.conf`, ticket cache (`KRB5CCNAME`, after `kinit`) and keytabs (`KRB5_KTNAME`)
//! exactly as they do, and rcp carries no Kerberos code of its own and links no Kerberos
//! library: a host without the library gets a clear refusal when Kerberos is asked for, and
//! nothing else changes.
//!
//! Two callers: RPCSEC_GSS in `nfs::rpc` (context tokens, MICs over headers, wrapped
//! bodies) and SPNEGO for WebHDFS in `hdfs::client` (one token in an `Authorization`
//! header). The stand-in servers use the acceptor side, so the contract suite exercises both
//! ends against a real KDC.

use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::io;
use std::ptr;
use std::sync::OnceLock;

type OmU32 = u32;

#[repr(C)]
struct Buffer {
    length: usize,
    value: *mut c_void,
}

impl Buffer {
    fn empty() -> Buffer {
        Buffer {
            length: 0,
            value: ptr::null_mut(),
        }
    }
    fn of(bytes: &[u8]) -> Buffer {
        Buffer {
            length: bytes.len(),
            value: bytes.as_ptr() as *mut c_void,
        }
    }
    /// Copies the bytes out; the caller releases the buffer afterwards.
    fn to_vec(&self) -> Vec<u8> {
        if self.value.is_null() || self.length == 0 {
            return Vec::new();
        }
        // SAFETY: the library filled `value` with `length` bytes.
        unsafe { std::slice::from_raw_parts(self.value as *const u8, self.length).to_vec() }
    }
}

#[repr(C)]
struct OidDesc {
    length: OmU32,
    elements: *mut c_void,
}

type GssName = *mut c_void;
type GssCtx = *mut c_void;
type GssCred = *mut c_void;
type GssOid = *mut OidDesc;

extern "C" {
    fn dlopen(filename: *const c_char, flag: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    fn dlerror() -> *const c_char;
}
const RTLD_NOW: c_int = 2;

type FnInit = unsafe extern "C" fn(
    *mut OmU32,
    GssCred,
    *mut GssCtx,
    GssName,
    GssOid,
    OmU32,
    OmU32,
    *mut c_void,
    *mut Buffer,
    *mut GssOid,
    *mut Buffer,
    *mut OmU32,
    *mut OmU32,
) -> OmU32;
type FnAccept = unsafe extern "C" fn(
    *mut OmU32,
    *mut GssCtx,
    GssCred,
    *mut Buffer,
    *mut c_void,
    *mut GssName,
    *mut GssOid,
    *mut Buffer,
    *mut OmU32,
    *mut OmU32,
    *mut GssCred,
) -> OmU32;
type FnAcquire = unsafe extern "C" fn(
    *mut OmU32,
    GssName,
    OmU32,
    *mut c_void,
    c_int,
    *mut GssCred,
    *mut *mut c_void,
    *mut OmU32,
) -> OmU32;
type FnReleaseCred = unsafe extern "C" fn(*mut OmU32, *mut GssCred) -> OmU32;
type FnImportName = unsafe extern "C" fn(*mut OmU32, *mut Buffer, GssOid, *mut GssName) -> OmU32;
type FnReleaseName = unsafe extern "C" fn(*mut OmU32, *mut GssName) -> OmU32;
type FnDisplayName = unsafe extern "C" fn(*mut OmU32, GssName, *mut Buffer, *mut GssOid) -> OmU32;
type FnMic = unsafe extern "C" fn(*mut OmU32, GssCtx, OmU32, *mut Buffer, *mut Buffer) -> OmU32;
type FnVerifyMic =
    unsafe extern "C" fn(*mut OmU32, GssCtx, *mut Buffer, *mut Buffer, *mut OmU32) -> OmU32;
type FnWrap = unsafe extern "C" fn(
    *mut OmU32,
    GssCtx,
    c_int,
    OmU32,
    *mut Buffer,
    *mut c_int,
    *mut Buffer,
) -> OmU32;
type FnUnwrap = unsafe extern "C" fn(
    *mut OmU32,
    GssCtx,
    *mut Buffer,
    *mut Buffer,
    *mut c_int,
    *mut OmU32,
) -> OmU32;
type FnReleaseBuffer = unsafe extern "C" fn(*mut OmU32, *mut Buffer) -> OmU32;
type FnDeleteCtx = unsafe extern "C" fn(*mut OmU32, *mut GssCtx, *mut Buffer) -> OmU32;
type FnDisplayStatus =
    unsafe extern "C" fn(*mut OmU32, OmU32, c_int, GssOid, *mut OmU32, *mut Buffer) -> OmU32;

struct Lib {
    init: FnInit,
    accept: FnAccept,
    acquire: FnAcquire,
    release_cred: FnReleaseCred,
    import_name: FnImportName,
    release_name: FnReleaseName,
    display_name: FnDisplayName,
    mic: FnMic,
    verify_mic: FnVerifyMic,
    wrap: FnWrap,
    unwrap: FnUnwrap,
    release_buffer: FnReleaseBuffer,
    delete_ctx: FnDeleteCtx,
    display_status: FnDisplayStatus,
}

// SAFETY: function pointers into a library that is never unloaded.
unsafe impl Send for Lib {}
unsafe impl Sync for Lib {}

const LIBRARIES: &[&str] = &[
    "libgssapi_krb5.so.2",
    "libgssapi_krb5.so",
    "libgssapi.so.3",
    "libgssapi.so",
];

/// DER-encoded object identifiers, as the library wants them (no tag or length byte).
/// 1.2.840.113554.1.2.2: the Kerberos 5 mechanism.
const OID_KRB5: [u8; 9] = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02];
/// 1.3.6.1.5.5.2: SPNEGO.
const OID_SPNEGO: [u8; 6] = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];
/// 1.2.840.113554.1.2.1.4: GSS_C_NT_HOSTBASED_SERVICE (`service@host`).
const OID_HOSTBASED: [u8; 10] = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x01, 0x04];

fn oid(bytes: &'static [u8]) -> OidDesc {
    OidDesc {
        length: bytes.len() as OmU32,
        elements: bytes.as_ptr() as *mut c_void,
    }
}

pub const GSS_C_MUTUAL_FLAG: u32 = 2;
pub const GSS_C_REPLAY_FLAG: u32 = 4;
pub const GSS_C_SEQUENCE_FLAG: u32 = 8;
pub const GSS_C_CONF_FLAG: u32 = 16;
pub const GSS_C_INTEG_FLAG: u32 = 32;
const GSS_C_ACCEPT: c_int = 2;
const GSS_C_INDEFINITE: OmU32 = 0xffff_ffff;
const GSS_C_GSS_CODE: c_int = 1;
const GSS_C_MECH_CODE: c_int = 2;
const GSS_S_CONTINUE_NEEDED: OmU32 = 1;

fn is_error(major: OmU32) -> bool {
    major & 0xffff_0000 != 0
}

static LIB: OnceLock<Result<Lib, String>> = OnceLock::new();

fn load() -> Result<Lib, String> {
    let mut last = String::new();
    for name in LIBRARIES {
        let c = CString::new(*name).expect("no NUL");
        // SAFETY: dlopen with a valid C string.
        let handle = unsafe { dlopen(c.as_ptr(), RTLD_NOW) };
        if handle.is_null() {
            // SAFETY: dlerror returns a static or NULL.
            last = unsafe {
                let e = dlerror();
                if e.is_null() {
                    format!("{name}: not found")
                } else {
                    CStr::from_ptr(e).to_string_lossy().into_owned()
                }
            };
            continue;
        }
        macro_rules! sym {
            ($t:ty, $n:literal) => {{
                let s = CString::new($n).expect("no NUL");
                // SAFETY: dlsym on a live handle; the pointer is only cast to the
                // prototype the library documents for that symbol.
                let p = unsafe { dlsym(handle, s.as_ptr()) };
                if p.is_null() {
                    return Err(format!("{name}: no symbol {}", $n));
                }
                // SAFETY: as above.
                unsafe { std::mem::transmute::<*mut c_void, $t>(p) }
            }};
        }
        return Ok(Lib {
            init: sym!(FnInit, "gss_init_sec_context"),
            accept: sym!(FnAccept, "gss_accept_sec_context"),
            acquire: sym!(FnAcquire, "gss_acquire_cred"),
            release_cred: sym!(FnReleaseCred, "gss_release_cred"),
            import_name: sym!(FnImportName, "gss_import_name"),
            release_name: sym!(FnReleaseName, "gss_release_name"),
            display_name: sym!(FnDisplayName, "gss_display_name"),
            mic: sym!(FnMic, "gss_get_mic"),
            verify_mic: sym!(FnVerifyMic, "gss_verify_mic"),
            wrap: sym!(FnWrap, "gss_wrap"),
            unwrap: sym!(FnUnwrap, "gss_unwrap"),
            release_buffer: sym!(FnReleaseBuffer, "gss_release_buffer"),
            delete_ctx: sym!(FnDeleteCtx, "gss_delete_sec_context"),
            display_status: sym!(FnDisplayStatus, "gss_display_status"),
        });
    }
    Err(format!("no GSSAPI library could be loaded ({last}); install the Kerberos GSSAPI library (libgssapi-krb5-2 on Debian, krb5-libs on Red Hat) or use a dynamically linked rcp"))
}

fn lib() -> io::Result<&'static Lib> {
    match LIB.get_or_init(load) {
        Ok(l) => Ok(l),
        Err(e) => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("Kerberos: {e}"),
        )),
    }
}

/// Whether Kerberos can be used on this host at all; the reason when it cannot.
pub fn available() -> Result<(), String> {
    LIB.get_or_init(load)
        .as_ref()
        .map(|_| ())
        .map_err(|e| e.clone())
}

fn status_text(l: &Lib, major: OmU32, minor: OmU32, what: &str) -> io::Error {
    let mut text = String::new();
    for (code, kind) in [(major, GSS_C_GSS_CODE), (minor, GSS_C_MECH_CODE)] {
        if code == 0 {
            continue;
        }
        let mut ctx: OmU32 = 0;
        loop {
            let mut minor_status: OmU32 = 0;
            let mut buf = Buffer::empty();
            let mut mech = oid(&OID_KRB5);
            // SAFETY: valid out-pointers; the buffer is released after copying.
            let r = unsafe {
                (l.display_status)(
                    &mut minor_status,
                    code,
                    kind,
                    if kind == GSS_C_MECH_CODE {
                        &mut mech
                    } else {
                        ptr::null_mut()
                    },
                    &mut ctx,
                    &mut buf,
                )
            };
            if r != 0 {
                break;
            }
            let s = String::from_utf8_lossy(&buf.to_vec()).into_owned();
            // SAFETY: releasing a buffer the library allocated.
            unsafe { (l.release_buffer)(&mut minor_status, &mut buf) };
            if !text.is_empty() {
                text.push_str("; ");
            }
            text.push_str(&s);
            if ctx == 0 {
                break;
            }
        }
    }
    let kind = match (major >> 16) & 0xff {
        // GSS_S_NO_CRED (7), GSS_S_CREDENTIALS_EXPIRED (11), GSS_S_DEFECTIVE_CREDENTIAL (10)
        7 | 10 | 11 => io::ErrorKind::PermissionDenied,
        _ => io::ErrorKind::Other,
    };
    io::Error::new(
        kind,
        format!("{what}: {text} (GSS major {major:#x}, minor {minor})"),
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mech {
    Krb5,
    Spnego,
}

/// Acceptor credentials from the keytab (`KRB5_KTNAME`, else the system default), for a
/// server side: the stand-in servers of the contract suite.
pub struct AcceptorCred {
    lib: &'static Lib,
    cred: GssCred,
}

// SAFETY: the library is thread-safe; the handle is used behind a shared reference.
unsafe impl Send for AcceptorCred {}
unsafe impl Sync for AcceptorCred {}

impl AcceptorCred {
    pub fn acquire() -> io::Result<AcceptorCred> {
        let l = lib()?;
        let mut minor = 0;
        let mut cred: GssCred = ptr::null_mut();
        // SAFETY: GSS_C_NO_NAME and GSS_C_NO_OID_SET are null; valid out-pointer.
        let major = unsafe {
            (l.acquire)(
                &mut minor,
                ptr::null_mut(),
                GSS_C_INDEFINITE,
                ptr::null_mut(),
                GSS_C_ACCEPT,
                &mut cred,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        if is_error(major) {
            return Err(status_text(
                l,
                major,
                minor,
                "acquiring acceptor credentials from the keytab",
            ));
        }
        Ok(AcceptorCred { lib: l, cred })
    }
}

impl Drop for AcceptorCred {
    fn drop(&mut self) {
        let mut minor = 0;
        // SAFETY: releasing a credential handle the library gave.
        unsafe { (self.lib.release_cred)(&mut minor, &mut self.cred) };
    }
}

/// One step of context establishment: the token to send (may be empty), and whether the
/// context is now established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    pub token: Vec<u8>,
    pub complete: bool,
}

/// A security context, initiator or acceptor side. Used from one thread at a time, which
/// is how a connection uses it.
pub struct Context {
    lib: &'static Lib,
    ctx: GssCtx,
    target: Option<GssName>,
    mech: Mech,
    flags: u32,
    pub established: bool,
    /// The peer's principal, once known (the acceptor learns it from the first token).
    pub peer: Option<String>,
}

// SAFETY: see above; a context is owned by one connection.
unsafe impl Send for Context {}

impl Context {
    /// An initiator toward `service@host` (for example `nfs@filer`, `HTTP@namenode`), using
    /// the default credential (the ticket cache).
    pub fn initiator(target: &str, mech: Mech, flags: u32) -> io::Result<Context> {
        let l = lib()?;
        let mut minor = 0;
        let mut name: GssName = ptr::null_mut();
        let mut buf = Buffer::of(target.as_bytes());
        let mut nt = oid(&OID_HOSTBASED);
        // SAFETY: the buffer and OID outlive the call; valid out-pointer.
        let major = unsafe { (l.import_name)(&mut minor, &mut buf, &mut nt, &mut name) };
        if is_error(major) {
            return Err(status_text(
                l,
                major,
                minor,
                &format!("importing the name {target:?}"),
            ));
        }
        Ok(Context {
            lib: l,
            ctx: ptr::null_mut(),
            target: Some(name),
            mech,
            flags,
            established: false,
            peer: None,
        })
    }

    /// An acceptor with the given credentials.
    pub fn acceptor() -> io::Result<Context> {
        let l = lib()?;
        Ok(Context {
            lib: l,
            ctx: ptr::null_mut(),
            target: None,
            mech: Mech::Krb5,
            flags: 0,
            established: false,
            peer: None,
        })
    }

    /// The initiator's next step: the first call takes no input, later calls take the
    /// peer's token.
    pub fn init_step(&mut self, input: Option<&[u8]>) -> io::Result<Step> {
        let l = self.lib;
        let mut minor = 0;
        let mut inbuf = input.map(Buffer::of).unwrap_or_else(Buffer::empty);
        let mut out = Buffer::empty();
        let mut mech = match self.mech {
            Mech::Krb5 => oid(&OID_KRB5),
            Mech::Spnego => oid(&OID_SPNEGO),
        };
        let mut ret_flags = 0;
        // SAFETY: all pointers are valid for the call; the output buffer is released after
        // copying.
        let major = unsafe {
            (l.init)(
                &mut minor,
                ptr::null_mut(),
                &mut self.ctx,
                self.target.unwrap_or(ptr::null_mut()),
                &mut mech,
                self.flags,
                GSS_C_INDEFINITE,
                ptr::null_mut(),
                &mut inbuf,
                ptr::null_mut(),
                &mut out,
                &mut ret_flags,
                ptr::null_mut(),
            )
        };
        let token = out.to_vec();
        // SAFETY: releasing the output buffer.
        let mut release_minor = 0;
        unsafe { (l.release_buffer)(&mut release_minor, &mut out) };
        if is_error(major) {
            return Err(status_text(l, major, minor, "Kerberos context initiation"));
        }
        self.established = major & GSS_S_CONTINUE_NEEDED == 0;
        Ok(Step {
            token,
            complete: self.established,
        })
    }

    /// The acceptor's next step over the initiator's token.
    pub fn accept_step(&mut self, cred: &AcceptorCred, input: &[u8]) -> io::Result<Step> {
        let l = self.lib;
        let mut minor = 0;
        let mut inbuf = Buffer::of(input);
        let mut out = Buffer::empty();
        let mut src: GssName = ptr::null_mut();
        let mut ret_flags = 0;
        // SAFETY: as in `init_step`.
        let major = unsafe {
            (l.accept)(
                &mut minor,
                &mut self.ctx,
                cred.cred,
                &mut inbuf,
                ptr::null_mut(),
                &mut src,
                ptr::null_mut(),
                &mut out,
                &mut ret_flags,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        let token = out.to_vec();
        // SAFETY: releasing the output buffer.
        let mut release_minor = 0;
        unsafe { (l.release_buffer)(&mut release_minor, &mut out) };
        if !src.is_null() {
            let mut nb = Buffer::empty();
            let mut m2 = 0;
            // SAFETY: valid name handle and out-buffer.
            if unsafe { (l.display_name)(&mut m2, src, &mut nb, ptr::null_mut()) } == 0 {
                self.peer = Some(String::from_utf8_lossy(&nb.to_vec()).into_owned());
                // SAFETY: releasing the buffer.
                unsafe { (l.release_buffer)(&mut m2, &mut nb) };
            }
            // SAFETY: releasing the name.
            unsafe { (l.release_name)(&mut m2, &mut src) };
        }
        if is_error(major) {
            return Err(status_text(l, major, minor, "Kerberos context acceptance"));
        }
        self.established = major & GSS_S_CONTINUE_NEEDED == 0;
        Ok(Step {
            token,
            complete: self.established,
        })
    }

    pub fn mic(&self, data: &[u8]) -> io::Result<Vec<u8>> {
        let l = self.lib;
        let mut minor = 0;
        let mut msg = Buffer::of(data);
        let mut out = Buffer::empty();
        // SAFETY: valid buffers; output released after copying.
        let major = unsafe { (l.mic)(&mut minor, self.ctx, 0, &mut msg, &mut out) };
        let token = out.to_vec();
        // SAFETY: releasing the output buffer.
        let mut release_minor = 0;
        unsafe { (l.release_buffer)(&mut release_minor, &mut out) };
        if is_error(major) {
            return Err(status_text(l, major, minor, "computing a MIC"));
        }
        Ok(token)
    }

    pub fn verify_mic(&self, data: &[u8], mic: &[u8]) -> io::Result<()> {
        let l = self.lib;
        let mut minor = 0;
        let mut msg = Buffer::of(data);
        let mut tok = Buffer::of(mic);
        // SAFETY: valid buffers.
        let major =
            unsafe { (l.verify_mic)(&mut minor, self.ctx, &mut msg, &mut tok, ptr::null_mut()) };
        if is_error(major) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                status_text(l, major, minor, "verifying a MIC").to_string(),
            ));
        }
        Ok(())
    }

    /// Wraps `data`, encrypted when `conf` is set; an error if confidentiality was asked
    /// for and the context cannot provide it.
    pub fn wrap(&self, data: &[u8], conf: bool) -> io::Result<Vec<u8>> {
        let l = self.lib;
        let mut minor = 0;
        let mut msg = Buffer::of(data);
        let mut out = Buffer::empty();
        let mut conf_state: c_int = 0;
        // SAFETY: valid buffers; output released after copying.
        let major = unsafe {
            (l.wrap)(
                &mut minor,
                self.ctx,
                conf as c_int,
                0,
                &mut msg,
                &mut conf_state,
                &mut out,
            )
        };
        let wrapped = out.to_vec();
        // SAFETY: releasing the output buffer.
        let mut release_minor = 0;
        unsafe { (l.release_buffer)(&mut release_minor, &mut out) };
        if is_error(major) {
            return Err(status_text(l, major, minor, "wrapping a message"));
        }
        if conf && conf_state == 0 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "the context does not provide confidentiality",
            ));
        }
        Ok(wrapped)
    }

    /// `conf` is what the caller ASKED for, and it is checked against what the token
    /// actually carried. Under `krb5p` an unencrypted reply is a downgrade: the operator
    /// chose privacy and did not get it.
    ///
    /// `conf_state` must be READ here, not merely passed to `gss_unwrap` -- `wrap`, six
    /// lines above, makes the same check and refuses. Without it, a stand-in patched to
    /// answer `krb5p` with integrity-only tokens measures end to end as
    /// `copy: 1 files (25 bytes) ... STATUS: PASSED`, byte-identical to the encrypted
    /// control, with the plaintext on the wire and not one word about it in the output.
    ///
    /// The threat model, stated honestly: the session key is shared with the server, so
    /// this is a SERVER downgrading (misconfigured, or hostile), not a passive listener.
    /// That is still precisely what choosing `krb5p` over `krb5i` is for.
    pub fn unwrap(&self, data: &[u8], conf: bool) -> io::Result<Vec<u8>> {
        let l = self.lib;
        let mut minor = 0;
        let mut msg = Buffer::of(data);
        let mut out = Buffer::empty();
        let mut conf_state: c_int = 0;
        // SAFETY: valid buffers; output released after copying.
        let major = unsafe {
            (l.unwrap)(
                &mut minor,
                self.ctx,
                &mut msg,
                &mut out,
                &mut conf_state,
                ptr::null_mut(),
            )
        };
        let plain = out.to_vec();
        // SAFETY: releasing the output buffer.
        let mut release_minor = 0;
        unsafe { (l.release_buffer)(&mut release_minor, &mut out) };
        if is_error(major) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                status_text(l, major, minor, "unwrapping a message").to_string(),
            ));
        }
        if conf && conf_state == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the reply was not encrypted, and this run asked for privacy (-nfs.sec krb5p): the server answered with an integrity-only token",
            ));
        }
        Ok(plain)
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        let mut minor = 0;
        if !self.ctx.is_null() {
            // SAFETY: deleting a context the library created; no output token wanted.
            unsafe { (self.lib.delete_ctx)(&mut minor, &mut self.ctx, ptr::null_mut()) };
        }
        if let Some(mut n) = self.target.take() {
            // SAFETY: releasing a name the library imported.
            unsafe { (self.lib.release_name)(&mut minor, &mut n) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_library_loads_or_says_why() {
        match available() {
            Ok(()) => {
                // an initiator toward a service with no ticket for it fails at the first
                // step with a credential error, not a crash
                let mut c =
                    Context::initiator("nfs@no-such-host.invalid", Mech::Krb5, GSS_C_MUTUAL_FLAG)
                        .unwrap();
                let err = c.init_step(None).unwrap_err();
                assert!(err.to_string().contains("GSS major"), "{err}");
            }
            Err(e) => assert!(e.contains("GSSAPI")),
        }
    }
}
