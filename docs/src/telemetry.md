# Telemetry

None: rcp reports nothing about itself to anyone. What it *does* connect to is worth stating
precisely, because the short answer -- "only to the NFS server or S3 endpoint named on its
command line" -- is wrong: there are six other transports, and hosts beyond those.

rcp opens sockets to:

- the endpoints named on its command line -- NFS, S3, HDFS, OCI, WebDAV, `ssh://`, `sftp://`;
- with `-nodes`, every worker host it names, over `ssh`, whether or not any endpoint is an
  `ssh://` one;
- the hosts those endpoints hand it on to, which is a real hand-off rather than a detail:
  an OCI upload `Location`, an OCI bearer `realm`, and a WebHDFS 307 to a datanode are all
  hosts the *remote* chooses. On a railed run `-allow` bounds them, as the registry and
  WebHDFS sections above set out;
- the proxy the environment names for any of the above.

It reads: the catalog location; the AWS credential and config files for S3; the registry
login files in the order the container tools read them -- `REGISTRY_AUTH_FILE`,
`$XDG_RUNTIME_DIR/containers/auth.json`, `$DOCKER_CONFIG/config.json`, `~/.docker/config.json`;
the local passwd and group files to map owners by name; `/proc/self/mountinfo` for the
mount table; the TLS trust store for `https` -- `SSL_CERT_FILE`, `SSL_CERT_DIR`,
`AWS_CA_BUNDLE`, and the system bundle when none of those is set; and the files named by
`-reference`, `-umap`, `-gmap` and `-copybatch` when a command takes them; whatever `ssh` itself reads for `ssh://`, `sftp://` and `-nodes`; and, for
Kerberos, whatever the host's GSSAPI library reads (`krb5.conf`, the ticket cache, a keytab) --
and that library then dials the KDC, a host on no command line, which is a socket easy to
leave off a list like this one.
