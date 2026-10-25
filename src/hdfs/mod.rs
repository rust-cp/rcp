//! The HDFS adapter: `hdfs://` endpoints reached over WebHDFS, the REST face every Hadoop
//! namenode serves (`dfs.webhdfs.enabled`, on by default since Hadoop 2), on the HTTP client
//! the S3 adapter already has. Pseudo authentication (`user.name`), and SPNEGO against a
//! Kerberos-secured namenode through the system GSSAPI -- this said Kerberos was not
//! covered for as long as the code covered it.
//!
//! `hdfs://namenode:9870/path` names the namenode explicitly; `hdfs:///path` takes it from
//! `-hdfs.namenode`, `HDFS_NAMENODE` or `RCP_HDFS_NAMENODE`. Reads and writes follow the namenode's redirect to a
//! datanode, so the datanode names the cluster advertises must resolve from here.

pub mod client;
/// In-process WebHDFS stand-in used by the integration tests.
#[doc(hidden)]
pub mod testserver;

#[cfg(test)]
pub(crate) fn client_kind_of_status(status: u16) -> std::io::ErrorKind {
    client::kind_of_status(status)
}
