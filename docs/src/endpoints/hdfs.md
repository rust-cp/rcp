# HDFS over WebHDFS

`rcp copy /data hdfs://namenode:9870/backup/data` speaks WebHDFS, the REST face every
Hadoop namenode serves, on the same HTTP client as the S3 adapter: `LISTSTATUS`,
`GETFILESTATUS`, `OPEN` and `CREATE` (following the namenode's redirect to a datanode, so
the datanode names the cluster advertises must resolve from here), `MKDIRS`, `DELETE`,
`RENAME`, `SETPERMISSION`, `SETOWNER` and `SETTIMES`. `hdfs:///path` takes the namenode
from `-hdfs.namenode HOST:PORT`, `HDFS_NAMENODE` or `RCP_HDFS_NAMENODE`; `https://` namenodes need the `rustls` build.
Authentication is pseudo (`user.name`, from `HADOOP_USER_NAME` or the calling user) until a
namenode answers `401` with `WWW-Authenticate: Negotiate`, the secured cluster's challenge;
then one SPNEGO token for `HTTP@namenode` from the ticket cache is sent (the same GSSAPI
library and ticket cache as for NFS), the `hadoop.auth` cookie the namenode issues is kept
only for later requests to the exact issuing scheme, host and port. It is not forwarded to
other origins or downgraded HTTP connections. The datanode hops use the delegation token the namenode puts
into its redirects, as a secured cluster expects. No ticket means a refusal that names what
the namenode wanted.

What HDFS itself cannot hold: hard links (the second name is written again; `-nolinks`
says so up front), symlinks (every current release refuses `CREATESYMLINK`, and rcp reports
each one as a failure rather than dropping it; `-type f` leaves them out), extended
attributes, and sub-millisecond times (`verify` and `sync` treat a millisecond-truncated
time the way they treat rsync's zeroed nanoseconds: the same when the dropped part is zero).
Ownership is by name there, resolved through this host's passwd and group files in both
directions. The contract suite runs the client against an in-process stand-in namenode and
datanode backed by a directory (`src/hdfs/testserver.rs`); `scripts/interop.sh hdfs` runs it
against Apache Hadoop, and Hadoop's own client reads back what it wrote.
