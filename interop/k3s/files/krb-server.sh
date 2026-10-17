#!/bin/sh
# The Kerberos pod: an MIT KDC for the realm RCP.INTEROP and NFS-Ganesha exporting /export
# with RPCSEC_GSS only (krb5, krb5i, krb5p). The service key is nfs/krb, named after the
# host the client dials, since a client asks for nfs@<the host in its URL>.
set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get -qq update
apt-get -qq install -y --no-install-recommends \
    krb5-kdc krb5-admin-server nfs-ganesha nfs-ganesha-vfs rpcbind >/dev/null

cp /etc/rcp-krb/krb5.conf /etc/krb5.conf
mkdir -p /etc/krb5kdc /var/lib/krb5kdc
cat >/etc/krb5kdc/kdc.conf <<EOF
[kdcdefaults]
    kdc_ports = 88
    kdc_tcp_ports = 88
[realms]
    RCP.INTEROP = {
        database_name = /var/lib/krb5kdc/principal
        key_stash_file = /etc/krb5kdc/stash
        acl_file = /etc/krb5kdc/kadm5.acl
        supported_enctypes = aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal
    }
EOF
: >/etc/krb5kdc/kadm5.acl
kdb5_util create -s -r RCP.INTEROP -P "$(cat /etc/rcp-krb-secret/master)" >/dev/null
kadmin.local -q "addprinc -pw $(cat /etc/rcp-krb-secret/user) rcpuser" >/dev/null
kadmin.local -q "addprinc -randkey nfs/krb" >/dev/null
kadmin.local -q "ktadd -k /etc/krb5.keytab nfs/krb" >/dev/null
krb5kdc

# the principal maps to a local user, as on any Kerberos NFS server: idmapd strips the
# local realm from rcpuser@RCP.INTEROP and looks the name up (unmapped, it is the anonymous
# uid, which may write into the destinations but not set their times)
useradd -M -u 1000 rcpuser
printf '%s\n' '[General]' 'Domain = rcp.interop' 'Local-Realms = RCP.INTEROP' \
    '[Translation]' 'Method = nsswitch' >/etc/idmapd.conf
# one destination per flavor, owned by that user and made before the server starts: an NFS
# URL mounts its whole path, and nothing may change the export under Ganesha
mkdir -p /export/krb5 /export/krb5i /export/krb5p /export/krb5p-v4
chown rcpuser: /export/krb5 /export/krb5i /export/krb5p /export/krb5p-v4

cat >/etc/ganesha/ganesha.conf <<EOF
NFS_CORE_PARAM { NFS_Port = 2049; MNT_Port = 20048; Enable_NLM = false; Enable_RQUOTA = false;
    Protocols = 3, 4; Enable_UDP = false; allow_set_io_flusher_fail = true; }
NFS_KRB5 { PrincipalName = nfs; KeytabPath = /etc/krb5.keytab; Active_krb5 = true; }
NFSV4 { Graceless = true; }
EXPORT {
    Export_Id = 1; Path = /export; Pseudo = /export;
    Access_Type = RW; Squash = No_Root_Squash; SecType = krb5, krb5i, krb5p;
    Protocols = 3, 4; Transports = TCP;
    FSAL { Name = VFS; }
}
EOF
# Ganesha's VFS layer finds the export's filesystem in the mount table, which this image
# does not link, and /export is an emptyDir so that it is a mount of its own
ln -sf /proc/self/mounts /etc/mtab
mkdir -p /var/run/ganesha /var/lib/nfs/ganesha /run/rpcbind
rpcbind -w
exec ganesha.nfsd -F -L /dev/stdout -f /etc/ganesha/ganesha.conf
