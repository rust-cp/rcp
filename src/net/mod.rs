//! Network plumbing shared by the HTTP-speaking endpoints: an HTTP/1.1 client with proxy
//! support, and TLS through rustls when the `rustls` feature is on.

pub mod http;
#[cfg(any(feature = "dav", feature = "https"))]
pub mod origin;
#[cfg(feature = "rustls")]
pub mod tls;
