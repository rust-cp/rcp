//! Just enough XML for the S3 responses rcp reads: element text by tag name, repeated
//! blocks, and entity unescaping. The service's documents are flat, unprefixed and
//! well-formed, which is all this handles.

/// The inner text of the first `<tag>...</tag>` in `xml`, raw (still escaped).
pub fn text<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(&xml[start..end])
}

/// Unescaped text of the first `<tag>`.
pub fn value(xml: &str, tag: &str) -> Option<String> {
    text(xml, tag).map(unescape)
}

/// The inner text of every `<tag>...</tag>` block, in document order.
pub fn blocks<'a>(xml: &'a str, tag: &str) -> Vec<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(s) = rest.find(&open) {
        let body = &rest[s + open.len()..];
        let Some(e) = body.find(&close) else { break };
        out.push(&body[..e]);
        rest = &body[e + close.len()..];
    }
    out
}

pub fn unescape(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        rest = &rest[i..];
        let Some(semi) = rest.find(';') else {
            out.push_str(rest);
            return out;
        };
        let entity = &rest[1..semi];
        match entity {
            "amp" => out.push('&'),
            "lt" => out.push('<'),
            "gt" => out.push('>'),
            "quot" => out.push('"'),
            "apos" => out.push('\''),
            _ => {
                let code = entity
                    .strip_prefix("#x")
                    .and_then(|h| u32::from_str_radix(h, 16).ok())
                    .or_else(|| entity.strip_prefix('#').and_then(|d| d.parse().ok()));
                match code.and_then(char::from_u32) {
                    Some(c) => out.push(c),
                    None => out.push_str(&rest[..=semi]),
                }
            }
        }
        rest = &rest[semi + 1..];
    }
    out.push_str(rest);
    out
}

pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_a_listing_shape() {
        let doc = "<ListBucketResult><IsTruncated>true</IsTruncated><Contents><Key>a&amp;b</Key><Size>3</Size></Contents><Contents><Key>c</Key><Size>0</Size></Contents></ListBucketResult>";
        assert_eq!(value(doc, "IsTruncated").as_deref(), Some("true"));
        let items: Vec<(String, String)> = blocks(doc, "Contents")
            .iter()
            .map(|b| (value(b, "Key").unwrap(), value(b, "Size").unwrap()))
            .collect();
        assert_eq!(
            items,
            vec![
                ("a&b".to_string(), "3".to_string()),
                ("c".to_string(), "0".to_string())
            ]
        );
        assert!(value(doc, "NextContinuationToken").is_none());
        assert_eq!(
            unescape("&lt;x&gt; &#65;&#x42; &bogus; &amp"),
            "<x> AB &bogus; &amp"
        );
        assert_eq!(escape("a<b>&\"c\""), "a&lt;b&gt;&amp;&quot;c&quot;");
    }
}
