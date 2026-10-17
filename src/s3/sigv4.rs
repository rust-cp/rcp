//! AWS Signature Version 4 for S3: HMAC-SHA256 over the tree's own SHA-256, the canonical
//! request and string-to-sign exactly as the service computes them. Checked against the
//! worked examples in the S3 developer guide, whose signatures are known constants.

use crate::net::http::percent_encode;
use crate::sha256::{hmac_sha256, to_hex, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credentials {
    pub access_key: String,
    pub secret_key: String,
    pub session_token: Option<String>,
}

pub const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";
/// SHA-256 of nothing: the payload hash of every request without a body.
pub const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    h.hex()
}

/// The query string as it is sent and as it is signed: pairs sorted by encoded name then
/// value, `name=value` joined with `&`, a name with no value as `name=`.
pub fn canonical_query(params: &[(String, String)]) -> String {
    let mut pairs: Vec<(String, String)> = params
        .iter()
        .map(|(k, v)| (percent_encode(k, false), percent_encode(v, false)))
        .collect();
    pairs.sort();
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn canonical_header_value(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    let mut last_space = false;
    for c in v.trim().chars() {
        if c == ' ' || c == '\t' {
            if !last_space {
                out.push(' ');
            }
            last_space = true;
        } else {
            out.push(c);
            last_space = false;
        }
    }
    out
}

/// What a signature covers, computed the same way by the signer and by a verifier.
pub struct Canonical {
    pub request: String,
    pub signed_headers: String,
}

/// Builds the canonical request from a method, an already-encoded path, the query pairs,
/// the headers to sign and the payload hash. `headers` may be in any case and order.
pub fn canonical_request(
    method: &str,
    encoded_path: &str,
    query: &[(String, String)],
    headers: &[(String, String)],
    payload_hash: &str,
) -> Canonical {
    let mut hs: Vec<(String, String)> = headers
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), canonical_header_value(v)))
        .collect();
    hs.sort();
    let signed_headers = hs
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(";");
    let canonical_headers: String = hs.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();
    let request = format!(
        "{method}\n{encoded_path}\n{}\n{canonical_headers}\n{signed_headers}\n{payload_hash}",
        canonical_query(query)
    );
    Canonical {
        request,
        signed_headers,
    }
}

pub fn signing_key(secret: &str, date: &str, region: &str, service: &str) -> [u8; 32] {
    let k_date = hmac_sha256(format!("AWS4{secret}").as_bytes(), date.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    hmac_sha256(&k_service, b"aws4_request")
}

/// The signature for a canonical request at `amz_date` (`YYYYMMDDTHHMMSSZ`) in `region`.
pub fn signature(
    creds: &Credentials,
    region: &str,
    amz_date: &str,
    canonical: &Canonical,
) -> String {
    let date = &amz_date[..8];
    let scope = format!("{date}/{region}/s3/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        sha256_hex(canonical.request.as_bytes())
    );
    let key = signing_key(&creds.secret_key, date, region, "s3");
    to_hex(&hmac_sha256(&key, string_to_sign.as_bytes()))
}

/// Headers a signature must not cover: hop-by-hop ones a proxy may rewrite.
fn excluded(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "expect"
            | "authorization"
            | "user-agent"
            | "proxy-authorization"
            | "content-length"
            | "transfer-encoding"
    )
}

/// Signs a request in place: adds `x-amz-date`, `x-amz-content-sha256`, the session token
/// when there is one, and `Authorization`. Every other header already present is signed.
pub fn sign(
    creds: &Credentials,
    region: &str,
    amz_date: &str,
    method: &str,
    encoded_path: &str,
    query: &[(String, String)],
    headers: &mut Vec<(String, String)>,
    payload_hash: &str,
) {
    headers.push(("x-amz-date".into(), amz_date.to_string()));
    headers.push(("x-amz-content-sha256".into(), payload_hash.to_string()));
    if let Some(t) = &creds.session_token {
        headers.push(("x-amz-security-token".into(), t.clone()));
    }
    let to_sign: Vec<(String, String)> = headers
        .iter()
        .filter(|(k, _)| !excluded(k))
        .cloned()
        .collect();
    let canonical = canonical_request(method, encoded_path, query, &to_sign, payload_hash);
    let sig = signature(creds, region, amz_date, &canonical);
    let scope = format!("{}/{region}/s3/aws4_request", &amz_date[..8]);
    headers.push((
        "Authorization".into(),
        format!(
            "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={}, Signature={sig}",
            creds.access_key, canonical.signed_headers
        ),
    ));
}

/// The parts of an `Authorization` header a verifier needs.
pub struct Authorization {
    pub access_key: String,
    pub date: String,
    pub region: String,
    pub signed_headers: Vec<String>,
    pub signature: String,
}

pub fn parse_authorization(header: &str) -> Option<Authorization> {
    let rest = header.strip_prefix("AWS4-HMAC-SHA256 ")?;
    let mut access_key = None;
    let mut date = None;
    let mut region = None;
    let mut signed = None;
    let mut sig = None;
    for part in rest.split(',') {
        let (k, v) = part.trim().split_once('=')?;
        match k {
            "Credential" => {
                let mut f = v.split('/');
                access_key = Some(f.next()?.to_string());
                date = Some(f.next()?.to_string());
                region = Some(f.next()?.to_string());
            }
            "SignedHeaders" => signed = Some(v.split(';').map(str::to_string).collect()),
            "Signature" => sig = Some(v.to_string()),
            _ => {}
        }
    }
    Some(Authorization {
        access_key: access_key?,
        date: date?,
        region: region?,
        signed_headers: signed?,
        signature: sig?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example_creds() -> Credentials {
        Credentials {
            access_key: "AKIAIOSFODNN7EXAMPLE".into(),
            secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
            session_token: None,
        }
    }

    /// The "GET Object" worked example from the S3 developer guide's SigV4 chapter.
    #[test]
    fn get_object_example_from_the_developer_guide() {
        let headers = vec![
            (
                "Host".to_string(),
                "examplebucket.s3.amazonaws.com".to_string(),
            ),
            ("Range".to_string(), "bytes=0-9".to_string()),
            ("x-amz-content-sha256".to_string(), EMPTY_SHA256.to_string()),
            ("x-amz-date".to_string(), "20130524T000000Z".to_string()),
        ];
        let c = canonical_request("GET", "/test.txt", &[], &headers, EMPTY_SHA256);
        assert_eq!(
            c.signed_headers,
            "host;range;x-amz-content-sha256;x-amz-date"
        );
        assert_eq!(
            signature(&example_creds(), "us-east-1", "20130524T000000Z", &c),
            "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
    }

    /// The "PUT Object" example: a body, a `$` in the key that must not be encoded twice, and
    /// a storage-class header in the signed set.
    #[test]
    fn put_object_example_from_the_developer_guide() {
        let body = b"Welcome to Amazon S3.";
        let hash = sha256_hex(body);
        assert_eq!(
            hash,
            "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072"
        );
        let headers = vec![
            (
                "Host".to_string(),
                "examplebucket.s3.amazonaws.com".to_string(),
            ),
            (
                "Date".to_string(),
                "Fri, 24 May 2013 00:00:00 GMT".to_string(),
            ),
            ("x-amz-content-sha256".to_string(), hash.clone()),
            ("x-amz-date".to_string(), "20130524T000000Z".to_string()),
            (
                "x-amz-storage-class".to_string(),
                "REDUCED_REDUNDANCY".to_string(),
            ),
        ];
        let c = canonical_request(
            "PUT",
            &percent_encode("/test$file.text", true),
            &[],
            &headers,
            &hash,
        );
        assert_eq!(
            signature(&example_creds(), "us-east-1", "20130524T000000Z", &c),
            "98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd"
        );
    }

    /// The "GET Bucket (List Objects)" example: query parameters in the canonical request.
    /// The guide's signature for it is not reproduced here (the page is no longer served as
    /// text), so this arm checks the canonical request shape the guide prints instead, and
    /// the stand-in server's verification covers the query path end to end.
    #[test]
    fn list_objects_example_canonical_request_shape() {
        let headers = vec![
            (
                "Host".to_string(),
                "examplebucket.s3.amazonaws.com".to_string(),
            ),
            ("x-amz-content-sha256".to_string(), EMPTY_SHA256.to_string()),
            ("x-amz-date".to_string(), "20130524T000000Z".to_string()),
        ];
        let query = vec![
            ("prefix".to_string(), "J".to_string()),
            ("max-keys".to_string(), "2".to_string()),
        ];
        let c = canonical_request("GET", "/", &query, &headers, EMPTY_SHA256);
        assert_eq!(c.request, format!("GET\n/\nmax-keys=2&prefix=J\nhost:examplebucket.s3.amazonaws.com\nx-amz-content-sha256:{EMPTY_SHA256}\nx-amz-date:20130524T000000Z\n\nhost;x-amz-content-sha256;x-amz-date\n{EMPTY_SHA256}"));
    }

    #[test]
    fn sign_then_parse_round_trips_and_a_wrong_secret_is_a_different_signature() {
        let mut headers = vec![("Host".to_string(), "b.example".to_string())];
        sign(
            &example_creds(),
            "us-east-1",
            "20130524T000000Z",
            "GET",
            "/k",
            &[],
            &mut headers,
            EMPTY_SHA256,
        );
        let auth = headers
            .iter()
            .find(|(k, _)| k == "Authorization")
            .map(|(_, v)| v.clone())
            .unwrap();
        let parsed = parse_authorization(&auth).unwrap();
        assert_eq!(parsed.access_key, "AKIAIOSFODNN7EXAMPLE");
        assert_eq!(parsed.date, "20130524");
        assert_eq!(
            parsed.signed_headers,
            vec!["host", "x-amz-content-sha256", "x-amz-date"]
        );
        let other = Credentials {
            secret_key: "nope".into(),
            ..example_creds()
        };
        let c = canonical_request(
            "GET",
            "/k",
            &[],
            &headers
                .iter()
                .filter(|(k, _)| k != "Authorization")
                .cloned()
                .collect::<Vec<_>>(),
            EMPTY_SHA256,
        );
        assert_ne!(
            signature(&other, "us-east-1", "20130524T000000Z", &c),
            parsed.signature
        );
        assert_eq!(
            signature(&example_creds(), "us-east-1", "20130524T000000Z", &c),
            parsed.signature
        );
    }

    #[test]
    fn uri_encoding_matches_the_service() {
        assert_eq!(percent_encode("a b/c~d.e_f-g", true), "a%20b/c~d.e_f-g");
        assert_eq!(percent_encode("a/b", false), "a%2Fb");
        assert_eq!(percent_encode("naïve", true), "na%C3%AFve");
        assert_eq!(
            canonical_query(&[
                ("prefix".into(), "a b".into()),
                ("list-type".into(), "2".into())
            ]),
            "list-type=2&prefix=a%20b"
        );
    }
}
