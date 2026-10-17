//! A small JSON reader for WebHDFS replies: objects, arrays, strings, numbers, booleans and
//! null, into a tree that the client walks by key. Numbers stay as text until asked, since
//! `length` and `modificationTime` need 64 bits and nothing needs floats.

use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Number(String),
    Str(String),
    Array(Vec<Json>),
    Object(BTreeMap<String, Json>),
}

impl Json {
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Object(m) => m.get(key),
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Json::Number(n) => n.parse().ok(),
            Json::Str(s) => s.parse().ok(),
            _ => None,
        }
    }
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Json::Number(n) => n.parse().ok(),
            _ => None,
        }
    }
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(b) => Some(*b),
            _ => None,
        }
    }
    pub fn as_array(&self) -> Option<&[Json]> {
        match self {
            Json::Array(a) => Some(a),
            _ => None,
        }
    }
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
    depth: usize,
}

impl<'a> Parser<'a> {
    fn ws(&mut self) {
        while self.i < self.s.len() && matches!(self.s[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }
    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }
    fn expect(&mut self, b: u8) -> Result<(), String> {
        if self.peek() == Some(b) {
            self.i += 1;
            Ok(())
        } else {
            Err(format!("expected {:?} at byte {}", b as char, self.i))
        }
    }
    fn value(&mut self) -> Result<Json, String> {
        if self.depth >= 128 {
            return Err("JSON nesting exceeds 128 values".into());
        }
        self.depth += 1;
        let result = self.value_inner();
        self.depth -= 1;
        result
    }

    fn value_inner(&mut self) -> Result<Json, String> {
        self.ws();
        match self.peek() {
            Some(b'{') => {
                self.i += 1;
                let mut m = BTreeMap::new();
                self.ws();
                if self.peek() == Some(b'}') {
                    self.i += 1;
                    return Ok(Json::Object(m));
                }
                loop {
                    self.ws();
                    let k = self.string()?;
                    self.ws();
                    self.expect(b':')?;
                    let v = self.value()?;
                    m.insert(k, v);
                    self.ws();
                    match self.peek() {
                        Some(b',') => self.i += 1,
                        Some(b'}') => {
                            self.i += 1;
                            return Ok(Json::Object(m));
                        }
                        _ => return Err(format!("expected ',' or '}}' at byte {}", self.i)),
                    }
                }
            }
            Some(b'[') => {
                self.i += 1;
                let mut a = Vec::new();
                self.ws();
                if self.peek() == Some(b']') {
                    self.i += 1;
                    return Ok(Json::Array(a));
                }
                loop {
                    a.push(self.value()?);
                    self.ws();
                    match self.peek() {
                        Some(b',') => self.i += 1,
                        Some(b']') => {
                            self.i += 1;
                            return Ok(Json::Array(a));
                        }
                        _ => return Err(format!("expected ',' or ']' at byte {}", self.i)),
                    }
                }
            }
            Some(b'"') => Ok(Json::Str(self.string()?)),
            Some(b't') if self.s[self.i..].starts_with(b"true") => {
                self.i += 4;
                Ok(Json::Bool(true))
            }
            Some(b'f') if self.s[self.i..].starts_with(b"false") => {
                self.i += 5;
                Ok(Json::Bool(false))
            }
            Some(b'n') if self.s[self.i..].starts_with(b"null") => {
                self.i += 4;
                Ok(Json::Null)
            }
            Some(c) if c == b'-' || c.is_ascii_digit() => {
                let start = self.i;
                if self.peek() == Some(b'-') {
                    self.i += 1;
                }
                match self.peek() {
                    Some(b'0') => self.i += 1,
                    Some(b'1'..=b'9') => {
                        self.i += 1;
                        while self.peek().is_some_and(|b| b.is_ascii_digit()) {
                            self.i += 1;
                        }
                    }
                    _ => return Err(format!("expected a number at byte {}", self.i)),
                }
                if self.peek() == Some(b'.') {
                    self.i += 1;
                    self.digits()?;
                }
                if matches!(self.peek(), Some(b'e' | b'E')) {
                    self.i += 1;
                    if matches!(self.peek(), Some(b'+' | b'-')) {
                        self.i += 1;
                    }
                    self.digits()?;
                }
                Ok(Json::Number(
                    String::from_utf8_lossy(&self.s[start..self.i]).to_string(),
                ))
            }
            Some(c) => Err(format!("unexpected {:?} at byte {}", c as char, self.i)),
            None => Err("unexpected end".into()),
        }
    }
    fn digits(&mut self) -> Result<(), String> {
        let start = self.i;
        while self.peek().is_some_and(|b| b.is_ascii_digit()) {
            self.i += 1;
        }
        if self.i == start {
            Err(format!("expected digits at byte {}", start))
        } else {
            Ok(())
        }
    }
    fn string(&mut self) -> Result<String, String> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            let Some(c) = self.peek() else {
                return Err("unterminated string".into());
            };
            self.i += 1;
            match c {
                b'"' => return Ok(out),
                0x00..=0x1f => return Err("unescaped control character in string".into()),
                b'\\' => {
                    let Some(e) = self.peek() else {
                        return Err("unterminated escape".into());
                    };
                    self.i += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let hex = self.s.get(self.i..self.i + 4).ok_or("short \\u escape")?;
                            self.i += 4;
                            let mut code = u32::from_str_radix(
                                std::str::from_utf8(hex).map_err(|_| "bad \\u escape")?,
                                16,
                            )
                            .map_err(|_| "bad \\u escape")?;
                            // a surrogate pair
                            if (0xD800..0xDC00).contains(&code)
                                && self.s.get(self.i..self.i + 2) == Some(b"\\u")
                            {
                                if let Some(lo) = self
                                    .s
                                    .get(self.i + 2..self.i + 6)
                                    .and_then(|h| std::str::from_utf8(h).ok())
                                    .and_then(|h| u32::from_str_radix(h, 16).ok())
                                {
                                    if (0xDC00..0xE000).contains(&lo) {
                                        code = 0x10000 + ((code - 0xD800) << 10) + (lo - 0xDC00);
                                        self.i += 6;
                                    }
                                }
                            }
                            out.push(char::from_u32(code).unwrap_or('\u{fffd}'));
                        }
                        other => return Err(format!("bad escape \\{}", other as char)),
                    }
                }
                _ => {
                    // Invalid UTF-8 is replaced. A fixed 2/3/4-byte grab also swallows the
                    // closing quote and the following JSON when the lead byte is not a
                    // real sequence, so only the non-ASCII run is consumed.
                    let start = self.i - 1;
                    if c < 0x80 {
                        out.push(c as char);
                    } else {
                        while self.peek().is_some_and(|b| b >= 0x80) {
                            self.i += 1;
                        }
                        out.push_str(&String::from_utf8_lossy(&self.s[start..self.i]));
                    }
                }
            }
        }
    }
}

/// Parses one complete JSON value, preserving number text without floating-point rounding.
///
/// # Errors
///
/// Returns a description for malformed syntax, trailing data, invalid number grammar,
/// unescaped string controls, or excessive nesting. This reader replaces invalid UTF-8
/// string sequences and unpaired Unicode surrogates rather than rejecting them.
///
/// # Examples
///
/// ```
/// use rcp::json::parse;
/// let value = parse(br#"{"length":18446744073709551615,"ready":true}"#)?;
/// assert_eq!(value.get("length").and_then(|v| v.as_u64()), Some(u64::MAX));
/// assert_eq!(value.get("ready").and_then(|v| v.as_bool()), Some(true));
/// assert!(parse(br#"{"length":1e}"#).is_err());
/// # Ok::<(), String>(())
/// ```
pub fn parse(text: &[u8]) -> Result<Json, String> {
    let mut p = Parser {
        s: text,
        i: 0,
        depth: 0,
    };
    let v = p.value()?;
    p.ws();
    if p.i != text.len() {
        return Err(format!("trailing data at byte {}", p.i));
    }
    Ok(v)
}

/// A JSON string literal for `s`.
///
/// ```
/// use rcp::json::{parse, quote};
/// let original = "quoted \"path\"\\line\n😀";
/// let encoded = quote(original);
/// assert_eq!(parse(encoded.as_bytes())?.as_str(), Some(original));
/// # Ok::<(), String>(())
/// ```
pub fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn excessive_nesting_is_rejected_without_overflowing_the_stack() {
        for (open, close) in [("[", "]"), ("{\"a\":", "}")] {
            let allowed = format!("{}0{}", open.repeat(127), close.repeat(127));
            assert!(parse(allowed.as_bytes()).is_ok());
            let excessive = format!("{}0{}", open.repeat(4096), close.repeat(4096));
            assert!(parse(excessive.as_bytes()).is_err());
        }
    }

    #[test]
    fn numbers_follow_json_grammar() {
        for invalid in [
            "-", "01", "-01", "1.", "1e", "1e+", "1-2", "1+2", "--1", "+1",
        ] {
            assert!(parse(invalid.as_bytes()).is_err(), "accepted {invalid}");
            let object = format!("{{\"id\":{invalid}}}");
            assert!(parse(object.as_bytes()).is_err(), "accepted {object}");
        }
        for valid in [
            "0", "-0", "12", "-12", "0.125", "-1.5", "1e10", "1E+10", "1e-10",
        ] {
            assert_eq!(parse(valid.as_bytes()).unwrap(), Json::Number(valid.into()));
        }
    }

    #[test]
    fn string_controls_must_be_escaped() {
        for control in 0u8..=31 {
            assert!(parse(&[b'"', control, b'"']).is_err());
            let escaped = format!("\"\\u{control:04x}\"");
            assert_eq!(
                parse(escaped.as_bytes()).unwrap().as_str(),
                Some(char::from(control).to_string().as_str())
            );
        }
    }

    #[test]
    fn parses_a_liststatus_reply() {
        let doc = r#"{"FileStatuses":{"FileStatus":[{"accessTime":0,"length":24930,"modificationTime":1320171722771,"owner":"webuser","pathSuffix":"a.patch","permission":"644","type":"FILE"},{"pathSuffix":"dir \u00e9\ud83d\ude00","type":"DIRECTORY","permission":"711","length":0}]}}"#;
        let v = parse(doc.as_bytes()).unwrap();
        let list = v
            .get("FileStatuses")
            .unwrap()
            .get("FileStatus")
            .unwrap()
            .as_array()
            .unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].get("length").unwrap().as_u64(), Some(24930));
        assert_eq!(
            list[0].get("modificationTime").unwrap().as_i64(),
            Some(1_320_171_722_771)
        );
        assert_eq!(
            list[1].get("pathSuffix").unwrap().as_str(),
            Some("dir \u{e9}\u{1f600}")
        );
        assert_eq!(
            parse(br#"{"boolean":true}"#)
                .unwrap()
                .get("boolean")
                .unwrap()
                .as_bool(),
            Some(true)
        );
        assert!(parse(b"{").is_err());
        assert!(parse(b"{} x").is_err());
        assert_eq!(quote("a\"b\\c\n\u{1}"), "\"a\\\"b\\\\c\\n\\u0001\"");
    }
}
