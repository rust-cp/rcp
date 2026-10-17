//! `show HOST`: what a server offers, asked over the wire:
//! the portmapper's registrations (which programs and versions, on which ports) and the
//! MOUNT protocol's export list. With `-v`, each export is mounted and asked for its
//! transfer sizes and free space.

use std::io;

use super::proto::*;
use super::rpc::{self, Connection, Credentials, Mapping, MOUNT_PROG, NFS_PROG};
use crate::human_bytes;

#[derive(Debug, Clone)]
pub struct ExportDetail {
    pub path: String,
    pub result: Result<(u32, u32, FsStat), String>,
}

#[derive(Debug, Clone)]
pub struct HostReport {
    pub host: String,
    pub services: Vec<Mapping>,
    pub exports: Vec<Export>,
    pub details: Vec<ExportDetail>,
}

/// The conventional name of an RPC program number.
pub fn program_name(prog: u32) -> String {
    match prog {
        100_000 => "portmapper",
        100_003 => "nfs",
        100_005 => "mountd",
        100_011 => "rquotad",
        100_021 => "nlockmgr",
        100_024 => "status",
        100_227 => "nfs_acl",
        100_001 => "rstatd",
        100_002 => "rusersd",
        100_008 => "walld",
        100_012 => "sprayd",
        400_010 => "nfs_v4_mig",
        _ => return prog.to_string(),
    }
    .to_string()
}

/// Asks `host` what it serves. The portmapper answer is required; a missing MOUNT service
/// leaves the export list empty rather than failing the report.
pub fn show(host: &str, verbose: bool) -> io::Result<HostReport> {
    let mut services = rpc::dump(host)
        .map_err(|e| io::Error::new(e.kind(), format!("{host}: portmapper: {e}")))?;
    services.sort_by_key(|m| (m.prog, m.vers, m.prot));
    let mut exports = Vec::new();
    let mut details = Vec::new();
    if let Ok(port) = rpc::getport(host, MOUNT_PROG, MOUNT_VERS) {
        let mut m = Connection::connect((host, port), Credentials::current())?;
        exports =
            res_exports(&m.call(MOUNT_PROG, MOUNT_VERS, MOUNTPROC_EXPORT, &args_exports())?)?;
        if verbose {
            let nfs_port = rpc::getport(host, NFS_PROG, NFS_VERS).unwrap_or(2049);
            for ex in &exports {
                let result = (|| -> io::Result<(u32, u32, FsStat)> {
                    let fh = res_mnt(&m.call(
                        MOUNT_PROG,
                        MOUNT_VERS,
                        MOUNTPROC_MNT,
                        &args_mnt(&ex.path),
                    )?)?;
                    let mut c = Connection::connect((host, nfs_port), Credentials::current())?;
                    let (rtmax, wtmax) =
                        res_fsinfo(&c.call(NFS_PROG, NFS_VERS, NFSPROC_FSINFO, &args_fh(&fh))?)?;
                    let stat =
                        res_fsstat(&c.call(NFS_PROG, NFS_VERS, NFSPROC_FSSTAT, &args_fh(&fh))?)?;
                    let _ = m.call(MOUNT_PROG, MOUNT_VERS, MOUNTPROC_UMNT, &args_mnt(&ex.path));
                    Ok((rtmax, wtmax, stat))
                })();
                details.push(ExportDetail {
                    path: ex.path.clone(),
                    result: result.map_err(|e| e.to_string()),
                });
            }
        }
    }
    Ok(HostReport {
        host: host.to_string(),
        services,
        exports,
        details,
    })
}

impl HostReport {
    pub fn render(&self) -> String {
        let mut out = format!(
            "host: {}\nservices:\n  {:<12} {:<8} {:<6} port\n",
            self.host, "program", "version", "proto"
        );
        for m in &self.services {
            let proto = match m.prot {
                6 => "tcp",
                17 => "udp",
                _ => "?",
            };
            out.push_str(&format!(
                "  {:<12} {:<8} {:<6} {}\n",
                program_name(m.prog),
                m.vers,
                proto,
                m.port
            ));
        }
        out.push_str("exports:\n");
        if self.exports.is_empty() {
            out.push_str("  (none, or no MOUNT service)\n");
        }
        for e in &self.exports {
            out.push_str(&format!(
                "  {:<40} {}\n",
                e.path,
                if e.groups.is_empty() {
                    "*".to_string()
                } else {
                    e.groups.join(", ")
                }
            ));
        }
        if !self.details.is_empty() {
            out.push_str("export details:\n");
            for d in &self.details {
                match &d.result {
                    Ok((rtmax, wtmax, st)) => out.push_str(&format!(
                        "  {:<40} rtmax {}  wtmax {}  total {}  free {}  files {} of {} free\n",
                        d.path,
                        human_bytes(*rtmax as u64),
                        human_bytes(*wtmax as u64),
                        human_bytes(st.total_bytes),
                        human_bytes(st.avail_bytes),
                        st.free_files,
                        st.total_files
                    )),
                    Err(e) => out.push_str(&format!("  {:<40} not mounted: {e}\n", d.path)),
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xdr::Encoder;

    #[test]
    fn export_lists_decode_as_linked_lists() {
        let mut e = Encoder::new();
        e.bool(true)
            .string("/vol/a")
            .bool(true)
            .string("10.0.0.0/24")
            .bool(true)
            .string("admin")
            .bool(false);
        e.bool(true).string("/vol/b").bool(false);
        e.bool(false);
        let got = res_exports(&e.into_bytes()).unwrap();
        assert_eq!(
            got,
            vec![
                Export {
                    path: "/vol/a".into(),
                    groups: vec!["10.0.0.0/24".into(), "admin".into()]
                },
                Export {
                    path: "/vol/b".into(),
                    groups: vec![]
                }
            ]
        );
        assert_eq!(program_name(100_003), "nfs");
        assert_eq!(program_name(7), "7");
    }
}
