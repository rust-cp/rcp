//! Where an `s3://` endpoint is and who rcp is when it gets there, resolved the way the AWS
//! tools resolve it: the command line's `-s3.*` options, then the `AWS_*` environment, then
//! the profile in `~/.aws/credentials` and `~/.aws/config`. No endpoint means AWS itself,
//! addressed virtual-hosted; any other endpoint (MinIO, ONTAP S3, a gateway) is path-style.

use std::collections::BTreeMap;
use std::io;
use std::path::PathBuf;

use super::sigv4::Credentials;
use crate::net::http::{proxy_from_env, Scheme, Target};

/// The four `-s3.*` options.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct S3Options {
    pub endpoint: Option<String>,
    pub profile: Option<String>,
    /// Plain HTTP when the endpoint names no scheme.
    pub insecure: bool,
    /// Skip certificate verification.
    pub noverify: bool,
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

impl S3Options {
    /// The environment's defaults: `RCP_S3_*`.
    pub fn from_env() -> S3Options {
        S3Options {
            endpoint: env("RCP_S3_ENDPOINT"),
            profile: env("RCP_S3_PROFILE"),
            insecure: env("RCP_S3_INSECURE").is_some(),
            noverify: env("RCP_S3_NOVERIFY").is_some(),
        }
    }
}

/// A parsed INI-style AWS file: section name (without a `profile ` prefix) to keys.
pub fn parse_ini(text: &str) -> BTreeMap<String, BTreeMap<String, String>> {
    let mut out: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    let mut section = String::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = name
                .trim()
                .strip_prefix("profile ")
                .unwrap_or(name.trim())
                .to_string();
            out.entry(section.clone()).or_default();
        } else if let Some((k, v)) = line.split_once('=') {
            if raw.starts_with(' ') || raw.starts_with('\t') {
                continue; // a nested block (s3 = / addressing_style), not needed here
            }
            out.entry(section.clone())
                .or_default()
                .insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    out
}

fn home() -> Option<PathBuf> {
    env("HOME").map(PathBuf::from)
}

fn profile_values(profile: &str) -> BTreeMap<String, String> {
    let mut merged = BTreeMap::new();
    let creds = env("AWS_SHARED_CREDENTIALS_FILE")
        .map(PathBuf::from)
        .or_else(|| home().map(|h| h.join(".aws/credentials")));
    let config = env("AWS_CONFIG_FILE")
        .map(PathBuf::from)
        .or_else(|| home().map(|h| h.join(".aws/config")));
    for path in [config, creds].into_iter().flatten() {
        if let Ok(text) = std::fs::read_to_string(&path) {
            if let Some(sec) = parse_ini(&text).remove(profile) {
                merged.extend(sec); // the credentials file wins over config, being last
            }
        }
    }
    merged
}

/// Everything a client needs to talk to one bucket.
#[derive(Clone)]
pub struct Resolved {
    pub target: Target,
    pub bucket: String,
    pub path_style: bool,
    pub region: String,
    pub creds: Option<Credentials>,
}

/// Splits `scheme://host[:port]` (the scheme optional) into its parts.
pub fn parse_endpoint(url: &str, insecure: bool) -> io::Result<(Scheme, String, u16)> {
    let url = url.trim();
    let (scheme, rest) = if let Some(r) = url.strip_prefix("https://") {
        (Scheme::Https, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (Scheme::Http, r)
    } else if url.contains("://") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("endpoint {url:?}: only http:// and https:// are supported"),
        ));
    } else {
        (
            if insecure {
                Scheme::Http
            } else {
                Scheme::Https
            },
            url,
        )
    };
    let hostport = rest.split('/').next().unwrap_or(rest).trim();
    // Userinfo, refused by name -- and the asymmetry with `net::http::split_url` is
    // deliberate, so it is written down here rather than left to be reported again as a
    // disagreement.
    //
    // `split_url` STRIPS userinfo, because what they parse is a URL a SERVER
    // handed back in a redirect, where the authority is whatever follows the `@` and a
    // legal redirect must be followed (`the_authority_of_a_redirect_is_what_follows_the_at_sign`
    // has both halves of that, with a control).
    //
    // This one parses a URL the OPERATOR TYPED. Stripping here would silently discard a
    // credential they wrote and send the run out unauthenticated, which is the worst of
    // the three outcomes: they would believe they had authenticated. Refusing says so.
    //
    // Without this check `user:pw@host` is still refused -- by accident, and with the wrong
    // reason: the `@` falls into the host, the host then contains a `:`, and the message
    // reads "an IPv6 address must be written in brackets". `http://user@host` has no colon,
    // so it is ACCEPTED, with a host of `user@host` that goes into the `Host:` header and
    // resolves nowhere.
    // And the message must not quote the URL back, because the URL is where the password
    // is. Every OTHER message in this function does quote it (`{url:?}`), so otherwise
    // `-s3.endpoint http://user:pw@host:70000` prints the password in a "bad port" error
    // and into whatever log caught stderr. The refusal below lands before any of them, so
    // no message in this function can carry userinfo -- which is why it is placed here
    // rather than after the split.
    if hostport.contains('@') {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "the endpoint URL carries a user and password; they do not go there (and are not repeated here). Use -s3.profile, or AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY".to_string()));
    }
    let default = if scheme == Scheme::Https { 443 } else { 80 };
    // Brackets first, NOT the `!h.contains(':')` guard on a last-colon split: with that
    // guard `[::1]:9000` never matches, so the WHOLE authority becomes the host and the
    // port silently becomes the scheme default. `-s3.endpoint http://[::1]:9000` would reach
    // a bucket on port 80 under a host called `[::1]:9000`.
    let (host, port) = if let Some(rest) = hostport.strip_prefix('[') {
        let (h, after) = rest.split_once(']').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("endpoint {url:?}: unterminated IPv6 literal"),
            )
        })?;
        if h.is_empty() || h.contains('[') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("endpoint {url:?}: malformed IPv6 literal"),
            ));
        }
        let p = match after.strip_prefix(':') {
            Some(p) if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("endpoint {url:?}: bad port"),
                ))
            }
            Some(p) => p.parse::<u16>().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("endpoint {url:?}: bad port"),
                )
            })?,
            None if after.is_empty() => default,
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("endpoint {url:?}: trailing text after the IPv6 literal"),
                ))
            }
        };
        (format!("[{h}]"), p)
    } else {
        match hostport.rsplit_once(':') {
            Some((h, p))
                if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) && !h.contains(':') =>
            {
                (
                    h.to_string(),
                    p.parse::<u16>().map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("endpoint {url:?}: bad port"),
                        )
                    })?,
                )
            }
            _ => (hostport.to_string(), default),
        }
    };
    if host.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("endpoint {url:?} has no host"),
        ));
    }
    if !host.starts_with('[') && host.contains(['[', ']']) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("endpoint {url:?}: a bracket in the host that is not an IPv6 literal"),
        ));
    }
    // The other readers refuse a bare IPv6 and this one accepted it, which is worse than a
    // parse disagreement: the host went on to the `Host:` header unbracketed, which is not
    // a legal authority, and the last-colon split had already taken part of the address
    // for a port. Refused by name here, as everywhere else.
    // `http://host:` ends in a colon with nothing after it, so the port guard above
    // declines to split and the whole thing becomes the host. It was then refused by the
    // IPv6 rule below, which is the right verdict reached for the wrong reason and
    // reported with a message about brackets that names nothing the operator wrote.
    if !host.starts_with('[') && host.ends_with(':') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("endpoint {url:?}: a colon with no port after it"),
        ));
    }
    if !host.starts_with('[') && host.contains(':') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("endpoint {url:?}: an IPv6 address must be written in brackets"),
        ));
    }
    Ok((scheme, host.to_string(), port))
}

/// Resolves the endpoint, region and credentials for `bucket`.
pub fn resolve(bucket: &str, opts: &S3Options) -> io::Result<Resolved> {
    let profile_name = opts
        .profile
        .clone()
        .or_else(|| env("AWS_PROFILE"))
        .unwrap_or_else(|| "default".into());
    let profile = profile_values(&profile_name);
    if opts.profile.is_some() && profile.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "-s3.profile {profile_name}: no such profile in the AWS credentials or config file"
            ),
        ));
    }
    let creds = match (env("AWS_ACCESS_KEY_ID"), env("AWS_SECRET_ACCESS_KEY")) {
        (Some(a), Some(s)) => Some(Credentials {
            access_key: a,
            secret_key: s,
            session_token: env("AWS_SESSION_TOKEN"),
        }),
        _ => match (
            profile.get("aws_access_key_id"),
            profile.get("aws_secret_access_key"),
        ) {
            (Some(a), Some(s)) => Some(Credentials {
                access_key: a.clone(),
                secret_key: s.clone(),
                session_token: profile.get("aws_session_token").cloned(),
            }),
            _ => None,
        },
    };
    let region = env("AWS_REGION")
        .or_else(|| env("AWS_DEFAULT_REGION"))
        .or_else(|| profile.get("region").cloned())
        .unwrap_or_else(|| "us-east-1".into());
    let endpoint = opts
        .endpoint
        .clone()
        .or_else(|| env("AWS_ENDPOINT_URL_S3"))
        .or_else(|| env("AWS_ENDPOINT_URL"))
        .or_else(|| profile.get("endpoint_url").cloned());
    let (scheme, host, port, path_style) = match endpoint {
        Some(url) => {
            let (s, h, p) = parse_endpoint(&url, opts.insecure)?;
            (s, h, p, true)
        }
        None => {
            let scheme = if opts.insecure {
                Scheme::Http
            } else {
                Scheme::Https
            };
            (
                scheme,
                format!("{bucket}.s3.{region}.amazonaws.com"),
                if scheme == Scheme::Https { 443 } else { 80 },
                false,
            )
        }
    };
    #[cfg(feature = "rustls")]
    let tls = if scheme == Scheme::Https {
        Some(crate::net::tls::config(
            opts.noverify,
            crate::net::tls::S3_NOVERIFY,
        )?)
    } else {
        None
    };
    #[cfg(not(feature = "rustls"))]
    if scheme == Scheme::Https {
        return Err(io::Error::new(io::ErrorKind::Unsupported, "https endpoint, but this rcp was built without the rustls feature: use -s3.insecure (http) or a build with --features rustls"));
    }
    let proxy = proxy_from_env(scheme, &host);
    let target = Target {
        scheme,
        host,
        port,
        proxy,
        #[cfg(feature = "rustls")]
        tls,
    };
    Ok(Resolved {
        target,
        bucket: bucket.to_string(),
        path_style,
        region,
        creds,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ini_sections_and_profile_prefixes() {
        let text = "[default]\naws_access_key_id = A\n# comment\n[profile lab]\nregion=us-gov-west-1\ns3 =\n    addressing_style = path\nendpoint_url = http://minio.lab:9000\n";
        let ini = parse_ini(text);
        assert_eq!(ini["default"]["aws_access_key_id"], "A");
        assert_eq!(ini["lab"]["region"], "us-gov-west-1");
        assert_eq!(ini["lab"]["endpoint_url"], "http://minio.lab:9000");
        assert!(!ini["lab"].contains_key("addressing_style"));
    }

    #[test]
    fn endpoints_parse_with_and_without_schemes() {
        assert_eq!(
            parse_endpoint("http://192.0.2.11:8082", false).unwrap(),
            (Scheme::Http, "192.0.2.11".into(), 8082)
        );
        assert_eq!(
            parse_endpoint("minio.lab:9000", true).unwrap(),
            (Scheme::Http, "minio.lab".into(), 9000)
        );
        assert_eq!(
            parse_endpoint("s3.example/", false).unwrap(),
            (Scheme::Https, "s3.example".into(), 443)
        );
        assert!(parse_endpoint("ftp://x", false).is_err());
        assert!(parse_endpoint("http://", false).is_err());
    }

    /// An operator-typed endpoint is not a redirect: userinfo in one is a credential they
    /// meant, so it is refused rather than dropped. `user:pw@` was already refused, for
    /// the wrong reason and with a message about IPv6 brackets; `user@` has no colon and
    /// was ACCEPTED, giving a host of `user@host` that goes into the `Host:` header.
    #[test]
    fn an_endpoint_that_carries_a_password_is_refused_without_repeating_it() {
        for url in [
            "http://user:hunter2@host:9000",
            "http://user@host",
            "https://a:b@h",
        ] {
            let e = parse_endpoint(url, false).unwrap_err().to_string();
            assert!(
                e.contains("do not go there"),
                "userinfo was not refused by name for {url}: {e}"
            );
            // the message must not quote the URL back, because the URL is where the
            // password is. Every other message in this function does quote it.
            assert!(
                !e.contains("hunter2") && !e.contains('@'),
                "the refusal repeated the credential for {url}: {e}"
            );
        }
        // the controls: an authority with no userinfo is untouched, and the `@` rule does
        // not reach into the PATH, where an `@` is an ordinary character
        assert_eq!(
            parse_endpoint("http://host:9000", false).unwrap(),
            (Scheme::Http, "host".into(), 9000)
        );
        assert_eq!(
            parse_endpoint("http://host/a@b", false).unwrap(),
            (Scheme::Http, "host".into(), 80)
        );
    }

    /// `http://host:` was refused, which is right, with "an IPv6 address must be written
    /// in brackets", which names nothing the operator wrote: the empty port made the guard
    /// decline to split, so the trailing colon ended up inside the host.
    #[test]
    fn a_colon_with_no_port_says_so_rather_than_blaming_ipv6() {
        let e = parse_endpoint("http://host:", false)
            .unwrap_err()
            .to_string();
        assert!(e.contains("a colon with no port after it"), "{e}");
        assert!(
            !e.contains("IPv6"),
            "the empty port is still reported as an IPv6 problem: {e}"
        );
        // the control: a real bare IPv6 still gets the bracket message, so the new arm
        // above has not simply taken it over
        let e = parse_endpoint("http://::1", false).unwrap_err().to_string();
        assert!(e.contains("must be written in brackets"), "{e}");
    }

    /// The endpoint parser reads an authority the way `net::http::split_url` does, except
    /// that userinfo is refused by name rather than stripped (see `parse_endpoint`).
    #[test]
    fn the_endpoint_parser_reads_bracketed_ipv6_with_a_port() {
        // A `!h.contains(':')` guard on a last-colon split reads `[::1]:9000` as a host of that
        // whole name on the scheme's default port. `-s3.endpoint` is the only way in, which is
        // why the shared table never covered it.
        let s3 = |u: &str| parse_endpoint(u, false).ok().map(|(_, h, p)| (h, p));
        for (url, want) in [
            ("http://[::1]:9000", Some(("[::1]".to_string(), 9000u16))),
            ("http://[::1]", Some(("[::1]".to_string(), 80))),
            ("https://[::1]", Some(("[::1]".to_string(), 443))),
            ("http://host:9000", Some(("host".to_string(), 9000))),
            ("http://[::1", None),
            ("http://[]:1", None),
            ("http://[::1]:+80", None),
            ("http://x]y", None),
        ] {
            assert_eq!(s3(url), want, "s3 endpoint: {url}");
        }

        // a bare IPv6 is refused here as it is by the other readers: accepted, it also
        // reached the `Host:` header unbracketed, which is not a legal authority
        assert_eq!(s3("http://::1"), None, "a bare IPv6 endpoint was accepted");
        assert_eq!(s3("http://::1:9000"), None);
    }
}
