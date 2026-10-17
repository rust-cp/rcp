//! Just enough XML to read a WebDAV `207 Multistatus`, and no more.
//!
//! This is deliberately NOT a general XML parser, because a general one is a much larger
//! thing to get right than this adapter needs and a much larger attack surface than it can
//! justify. A `PROPFIND` reply is a fixed shape -- `multistatus` containing `response`
//! elements, each with an `href` and one or more `propstat` -- and the only questions asked
//! of it are "what is this element called, in the `DAV:` namespace" and "what text is
//! inside it". So that is the whole interface: a pull parser over events.
//!
//! What it deliberately does not do, and why each is safe to omit here:
//!
//! - **Entity expansion beyond the five predefined ones.** No `DOCTYPE`, no external
//!   entities, so the billion-laughs and external-entity classes do not exist here rather
//!   than being defended against. A `<!DOCTYPE` is refused outright.
//! - **Attributes**, except `xmlns` and `xmlns:p`, which are read for the namespace, and
//!   the rest, which are skipped correctly -- including quoted `>` inside them, which is
//!   the one place a naive scanner goes wrong.
//!
//! What it DOES do: **resolve namespaces.** It is tempting to strip the prefix and compare the
//! local name, on the reasoning that every server binds `D:` to `DAV:` and no other element
//! is called `href`. That reasoning is about servers, and the reader is fed by anything that
//! answers on the port: a `<X:href xmlns:X="urn:other">` placed after the real one would be
//! read as the entry's path, and a foreign `<status>` carrying 500 would skip the entry. So an
//! element is reported only when its name resolves to `DAV:`; an element in any other
//! namespace is skipped WITH its subtree, and a `text()` or `child_names()` never sees it.
//! The one leniency, stated: an unprefixed element with NO default namespace declared
//! anywhere above it is read as `DAV:`, because a server that declares nothing is
//! unambiguous even though it is not conformant. `xmlns=""` is not that case: it is a
//! declaration, saying the element is in no namespace at all, and an element in no namespace
//! is not a `DAV:` one. The sentence above can be read two ways; this is the way the code
//! reads it, pinned by an arm.

use std::io;

/// One step through the document. `Text` carries decoded character data.
#[derive(Debug, PartialEq, Eq)]
pub enum Event<'a> {
    /// `<name ...>`; `empty` is true for `<name/>`, which never gets an `End`.
    Start {
        name: &'a str,
        empty: bool,
    },
    End {
        name: &'a str,
    },
    Text(String),
}

/// A tag or text as it sits in the source, before any namespace is resolved.
enum Raw<'a> {
    Start {
        qname: &'a str,
        attrs: &'a str,
        empty: bool,
    },
    End {
        qname: &'a str,
    },
    Text(String),
}

pub struct Reader<'a> {
    src: &'a str,
    pos: usize,
    /// Open elements, counted so bindings can be popped at the right `End`.
    depth: usize,
    /// The qualified names of the open elements, innermost last: an end tag has to name
    /// the element it closes. Depth alone accepted `<a><b></a></b>`, and a multistatus
    /// whose tags did not nest could be read as one whose statuses were fine.
    open: Vec<&'a str>,
    /// Namespace bindings in scope: the depth of the element that declared each, the
    /// prefix (`None` for the default namespace) and the URI.
    ///
    /// The URI is a `Cow` for one reason, and it is a leak rather than a nicety. A binding
    /// whose value carries a character reference -- `xmlns:D="DAV&#58;"` -- is not a slice
    /// of the input once decoded, and buying that lifetime with `Box::leak` is tempting.
    /// Every PROPFIND answered by a server that writes its namespace that way would then
    /// leak a String for the life of the process, which is unbounded in the one place it
    /// matters most: `rcp mcp`, a server that stays up across many walks. Borrowed when the
    /// value is already a slice (the common case, no allocation), owned when it had to be
    /// decoded, freed with the Reader either way.
    scopes: Vec<(usize, Option<&'a str>, std::borrow::Cow<'a, str>)>,
}

const DAV: &str = "DAV:";

/// A qualified name split at its prefix: `D:href` is (`Some("D")`, `href`).
fn split_qname(qname: &str) -> (Option<&str>, &str) {
    match qname.split_once(':') {
        Some((p, n)) => (Some(p), n),
        None => (None, qname),
    }
}

fn bad(what: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("the server's XML is not a multistatus this can read: {what}"),
    )
}

/// The five predefined entities and numeric character references. Anything else is left
/// alone rather than guessed at -- an unexpanded `&foo;` in a filename is visible and
/// wrong, which is better than a silently dropped character.
/// Bytes `decode` has looked at, counted in test builds only.
///
/// **A COMPLEXITY CLASS IS A PROPERTY OF THE WORK, AND THE WORK CAN BE COUNTED.** The arm
/// below used to time two runs and compare, which is a measurement of the machine as much
/// as of the function: it failed twice on a loaded one, the second time at the same `24.2`
/// the comment already recorded, and taking the best of five runs did not fix it because
/// the LARGE run is the one a scheduler is likeliest to preempt in every sample. This
/// counts the scan instead. It is exact, it is identical on a busy machine and an idle one,
/// and the quadratic it guards against cannot hide from it.
#[cfg(test)]
pub(crate) mod scanned {
    use std::cell::Cell;
    thread_local! {
        static N: Cell<u64> = const { Cell::new(0) };
    }
    pub(crate) fn note(n: usize) {
        N.with(|c| c.set(c.get() + n as u64));
    }
    pub(crate) fn reset() {
        N.with(|c| c.set(0));
    }
    pub(crate) fn count() -> u64 {
        N.with(Cell::get)
    }
}

#[cfg(test)]
fn note_scan(n: usize) {
    scanned::note(n);
}

/// Nothing at all outside a test build, so the hot path pays no counter.
#[cfg(not(test))]
#[inline(always)]
fn note_scan(_n: usize) {}

fn decode(s: &str) -> String {
    if !s.contains('&') {
        note_scan(s.len());
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        rest = &rest[i..];
        // Not `rest.find(';').filter(|e| *e <= 12)`: that scans the ENTIRE remainder before
        // applying the filter. A run of `&` with no nearby `;` then costs a full scan per
        // ampersand while advancing one byte: measured on a copy of this function, 320 KB of
        // `&` took 3.5 s and the cost quadrupled per doubling, so 10 MB is about an hour.
        // `decode` runs on every text node and every attribute value containing `&`, so one
        // hostile `<D:href>` would hang the whole PROPFIND walk.
        // The same 320 KB takes 3.9 ms with the bounded window below.
        //
        // The obvious one-liner -- `rest[..rest.len().min(13)].find(';')` -- PANICS when
        // byte 13 lands inside a multi-byte character, which is reachable from a server's
        // reply. Measured, and that is why this searches BYTES: a byte index needs no
        // character boundary, and `;` is ASCII so it cannot appear inside one.
        let window = rest.len().min(13);
        // what this iteration looked at: the bytes `find` passed over to reach the `&`,
        // the `&` itself, and the bounded window searched for the terminator
        note_scan(i + 1 + window);
        let Some(end) = rest.as_bytes()[..window].iter().position(|&b| b == b';') else {
            out.push('&');
            rest = &rest[1..];
            continue;
        };
        let body = &rest[1..end];
        let replacement = match body {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ => body
                .strip_prefix('#')
                .and_then(|n| match n.strip_prefix(['x', 'X']) {
                    Some(hex) => u32::from_str_radix(hex, 16).ok(),
                    None => n.parse::<u32>().ok(),
                })
                .and_then(char::from_u32),
        };
        match replacement {
            Some(c) => {
                out.push(c);
                rest = &rest[end + 1..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    // the last `find` scanned the whole remainder and found no `&`
    note_scan(rest.len());
    out.push_str(rest);
    out
}

/// The `name="value"` pairs of a tag's attribute text, in order. Malformed text ends the
/// iteration rather than failing the document: the attributes this reader cares about are
/// the namespace declarations, and a tag it cannot read the attributes of is a tag whose
/// namespace it cannot know -- which resolves as "not `DAV:`" below.
fn attrs(mut s: &str) -> Vec<(&str, &str)> {
    let mut out = Vec::new();
    loop {
        s = s.trim_start();
        if s.is_empty() {
            return out;
        }
        let Some(eq) = s.find('=') else { return out };
        let name = s[..eq].trim();
        let rest = s[eq + 1..].trim_start();
        let Some(q) = rest.chars().next().filter(|c| *c == '"' || *c == '\'') else {
            return out;
        };
        let body = &rest[1..];
        let Some(close) = body.find(q) else {
            return out;
        };
        out.push((name, &body[..close]));
        s = &body[close + 1..];
    }
}

impl<'a> Reader<'a> {
    pub fn new(src: &'a str) -> Reader<'a> {
        Reader {
            src,
            pos: 0,
            depth: 0,
            scopes: Vec::new(),
            open: Vec::new(),
        }
    }

    /// The next `DAV:` event, or `None` at the end of the document. Elements in another
    /// namespace are skipped together with everything inside them.
    #[expect(
        clippy::should_implement_trait,
        reason = "fallible: an I/O error is not an item"
    )]
    pub fn next(&mut self) -> io::Result<Option<Event<'a>>> {
        loop {
            let Some(raw) = self.raw()? else {
                return Ok(None);
            };
            match raw {
                Raw::Text(t) => return Ok(Some(Event::Text(t))),
                Raw::End { qname } => {
                    if self.depth == 0 {
                        return Err(bad(&format!(
                            "</{qname}> closes an element that was not open"
                        )));
                    }
                    match self.open.pop() {
                        Some(o) if o == qname => {}
                        Some(o) => {
                            return Err(bad(&format!(
                                "</{qname}> closes <{o}>, which is not the element open"
                            )))
                        }
                        None => {
                            return Err(bad(&format!(
                                "</{qname}> closes an element that was not open"
                            )))
                        }
                    }
                    let name = self.resolve(qname);
                    // bindings declared by the element now closing go out of scope
                    while self.scopes.last().is_some_and(|(d, _, _)| *d == self.depth) {
                        self.scopes.pop();
                    }
                    self.depth = self.depth.saturating_sub(1);
                    match name {
                        Some(n) => return Ok(Some(Event::End { name: n })),
                        // an End for an element `next` never reported: its Start was
                        // foreign and the subtree was skipped whole, so this is only
                        // reachable on a document whose tags do not nest -- reported so
                        // it is not silently dropped
                        None => {
                            return Err(bad(&format!(
                                "</{qname}> closes an element that was not open"
                            )))
                        }
                    }
                }
                Raw::Start {
                    qname,
                    attrs: a,
                    empty,
                } => {
                    let declared = self.depth + 1;
                    for (k, v) in attrs(a) {
                        // an attribute value may carry a character reference, and
                        // `xmlns:D="DAV&#58;"` is `DAV:` once it is read as XML says
                        let v: std::borrow::Cow<'a, str> = if v.contains('&') {
                            std::borrow::Cow::Owned(decode(v))
                        } else {
                            std::borrow::Cow::Borrowed(v)
                        };
                        if k == "xmlns" {
                            self.scopes.push((declared, None, v));
                        } else if let Some(p) = k.strip_prefix("xmlns:") {
                            self.scopes.push((declared, Some(p), v));
                        }
                    }
                    let name = self.resolve(qname);
                    if empty {
                        while self.scopes.last().is_some_and(|(d, _, _)| *d == declared) {
                            self.scopes.pop();
                        }
                        match name {
                            Some(n) => {
                                return Ok(Some(Event::Start {
                                    name: n,
                                    empty: true,
                                }))
                            }
                            None => continue,
                        }
                    }
                    self.depth = declared;
                    self.open.push(qname);
                    match name {
                        Some(n) => {
                            return Ok(Some(Event::Start {
                                name: n,
                                empty: false,
                            }))
                        }
                        None => {
                            self.skip_subtree(qname)?;
                            continue;
                        }
                    }
                }
            }
        }
    }

    /// The local name of `qname` if it resolves to `DAV:` in the current scope.
    fn resolve(&self, qname: &'a str) -> Option<&'a str> {
        let (prefix, local) = split_qname(qname);
        let binding = self
            .scopes
            .iter()
            .rev()
            .find(|(_, p, _)| *p == prefix)
            .map(|(_, _, uri)| &**uri);
        match (prefix, binding) {
            (_, Some(uri)) if uri == DAV => Some(local),
            (_, Some(_)) => None,
            // no prefix and no default namespace declared: read as DAV:, stated in the
            // module doc as the one leniency
            (None, None) => Some(local),
            // a prefix nothing binds is an error in the document; not ours to guess
            (Some(_), None) => None,
        }
    }

    /// Consumes through the end tag of the foreign element just opened, whose contents
    /// are nobody's business here. Nested elements are counted by raw depth, so a foreign
    /// element containing `<D:href>` hides that href too -- it is inside something this
    /// reader was told not to read.
    fn skip_subtree(&mut self, qname: &'a str) -> io::Result<()> {
        let mut inner = 0usize;
        loop {
            match self.raw()? {
                None => return Err(bad(&format!("<{qname}> is never closed"))),
                Some(Raw::Start { empty: false, .. }) => inner += 1,
                Some(Raw::End { .. }) if inner > 0 => inner -= 1,
                Some(Raw::End { qname: q }) => {
                    if q != qname {
                        return Err(bad(&format!(
                            "</{q}> closes <{qname}>, which is not the element open"
                        )));
                    }
                    self.open.pop();
                    while self.scopes.last().is_some_and(|(d, _, _)| *d == self.depth) {
                        self.scopes.pop();
                    }
                    self.depth = self.depth.saturating_sub(1);
                    return Ok(());
                }
                Some(_) => {}
            }
        }
    }

    /// The next tag or run of text, as written.
    fn raw(&mut self) -> io::Result<Option<Raw<'a>>> {
        loop {
            if self.pos >= self.src.len() {
                return Ok(None);
            }
            let rest = &self.src[self.pos..];
            if !rest.starts_with('<') {
                let end = rest.find('<').unwrap_or(rest.len());
                let text = &rest[..end];
                self.pos += end;
                if text.trim().is_empty() {
                    continue; // whitespace between elements is not character data anyone wants
                }
                return Ok(Some(Raw::Text(decode(text))));
            }
            // `<?xml ...?>` and comments are skipped; a DOCTYPE is refused rather than
            // skipped, because skipping one is how an entity-expansion parser pretends it
            // is not an entity-expansion parser.
            if rest.starts_with("<!DOCTYPE") || rest.starts_with("<!doctype") {
                return Err(bad(
                    "it carries a DOCTYPE, which this reader will not process",
                ));
            }
            if rest.starts_with("<!--") {
                let end = rest
                    .find("-->")
                    .ok_or_else(|| bad("an unterminated comment"))?;
                self.pos += end + 3;
                continue;
            }
            if rest.starts_with("<?") {
                let end = rest
                    .find("?>")
                    .ok_or_else(|| bad("an unterminated processing instruction"))?;
                self.pos += end + 2;
                continue;
            }
            if let Some(cdata) = rest.strip_prefix("<![CDATA[") {
                let end = cdata
                    .find("]]>")
                    .ok_or_else(|| bad("an unterminated CDATA section"))?;
                let text = &cdata[..end];
                self.pos += 9 + end + 3;
                if text.is_empty() {
                    continue;
                }
                return Ok(Some(Raw::Text(text.to_string())));
            }
            // A real tag. Find its `>`, skipping any inside a quoted attribute value --
            // the one thing a scanner that just looks for the next `>` gets wrong.
            let close = self.tag_end(rest)?;
            let inner = &rest[1..close];
            self.pos += close + 1;
            if let Some(name) = inner.strip_prefix('/') {
                return Ok(Some(Raw::End { qname: name.trim() }));
            }
            let (inner, empty) = match inner.strip_suffix('/') {
                Some(i) => (i, true),
                None => (inner, false),
            };
            let name_end = inner.find([' ', '\t', '\r', '\n']).unwrap_or(inner.len());
            let qname = &inner[..name_end];
            if qname.is_empty() {
                return Err(bad("an element with no name"));
            }
            return Ok(Some(Raw::Start {
                qname,
                attrs: &inner[name_end..],
                empty,
            }));
        }
    }

    /// The index of the `>` that closes the tag starting at `rest[0]`.
    fn tag_end(&self, rest: &str) -> io::Result<usize> {
        let b = rest.as_bytes();
        let mut i = 1;
        let mut quote = 0u8;
        while i < b.len() {
            match b[i] {
                q @ (b'"' | b'\'') if quote == 0 => quote = q,
                q if quote != 0 && q == quote => quote = 0,
                b'>' if quote == 0 => return Ok(i),
                _ => {}
            }
            i += 1;
        }
        Err(bad("an unterminated tag"))
    }

    /// The text directly inside the element just opened, consuming through its end tag.
    /// Nested elements are skipped; a property whose value is markup (`<resourcetype>`)
    /// is read with `child_names` instead.
    pub fn text(&mut self, name: &str) -> io::Result<String> {
        let mut out = String::new();
        let mut depth = 0usize;
        while let Some(e) = self.next()? {
            match e {
                Event::Text(t) if depth == 0 => out.push_str(&t),
                Event::Start { empty: false, .. } => depth += 1,
                Event::End { name: n } if depth == 0 && n == name => return Ok(out),
                Event::End { .. } => depth = depth.saturating_sub(1),
                _ => {}
            }
        }
        Err(bad(&format!("<{name}> is never closed")))
    }

    /// The names of the elements directly inside the element just opened. This is how
    /// `resourcetype` is read: it holds `<collection/>` or nothing at all, and the
    /// PRESENCE of the child is the answer rather than any text.
    pub fn child_names(&mut self, name: &str) -> io::Result<Vec<&'a str>> {
        let mut out = Vec::new();
        let mut depth = 0usize;
        while let Some(e) = self.next()? {
            match e {
                Event::Start { name: n, empty } => {
                    if depth == 0 {
                        out.push(n);
                    }
                    if !empty {
                        depth += 1;
                    }
                }
                Event::End { name: n } if depth == 0 && n == name => return Ok(out),
                Event::End { .. } => depth = depth.saturating_sub(1),
                Event::Text(_) => {}
            }
        }
        Err(bad(&format!("<{name}> is never closed")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn events(src: &str) -> Vec<String> {
        let mut r = Reader::new(src);
        let mut out = Vec::new();
        while let Some(e) = r.next().unwrap() {
            out.push(match e {
                Event::Start { name, empty } => format!("<{name}{}>", if empty { "/" } else { "" }),
                Event::End { name } => format!("</{name}>"),
                Event::Text(t) => format!("#{t}"),
            });
        }
        out
    }

    #[test]
    fn a_prefix_is_not_part_of_the_name_and_whitespace_is_not_text() {
        assert_eq!(
            events("<D:multistatus xmlns:D=\"DAV:\">\n  <D:href>/a</D:href>\n</D:multistatus>"),
            [
                "<multistatus>",
                "<href>",
                "#/a",
                "</href>",
                "</multistatus>"
            ]
        );
        // the control: a name with no prefix and no namespace reads the same, so the
        // reader is not just deleting everything before a colon it happens to find
        assert_eq!(
            events("<multistatus><href>/a</href></multistatus>"),
            [
                "<multistatus>",
                "<href>",
                "#/a",
                "</href>",
                "</multistatus>"
            ]
        );
    }

    /// The namespace, not the prefix, is what makes an element a `DAV:` one. `D:` bound
    /// to something else is foreign; `a:` bound to `DAV:` is not; and a foreign element
    /// takes its whole subtree with it, including a `DAV:` href hiding inside.
    #[test]
    fn an_element_is_read_by_its_namespace_and_not_by_its_prefix() {
        // the arm: a decoy href in another namespace, placed AFTER the real one, is not
        // read -- the prefix-stripping reader took it as the entry's path
        let doc = r#"<a:multistatus xmlns:a="DAV:"><a:response><a:href>/real</a:href><X:href xmlns:X="urn:other">/decoy</X:href></a:response></a:multistatus>"#;
        assert_eq!(
            events(doc),
            [
                "<multistatus>",
                "<response>",
                "<href>",
                "#/real",
                "</href>",
                "</response>",
                "</multistatus>"
            ]
        );
        // the same with the conventional prefix bound to the WRONG namespace: `D:` is
        // not magic
        let doc = r#"<multistatus xmlns="DAV:"><D:href xmlns:D="urn:other">/decoy</D:href><href>/real</href></multistatus>"#;
        assert_eq!(
            events(doc),
            [
                "<multistatus>",
                "<href>",
                "#/real",
                "</href>",
                "</multistatus>"
            ]
        );
        // a foreign element hides its subtree, DAV: children included
        let doc = r#"<multistatus xmlns="DAV:"><X:wrap xmlns:X="urn:other"><href>/hidden</href></X:wrap><href>/real</href></multistatus>"#;
        assert_eq!(
            events(doc),
            [
                "<multistatus>",
                "<href>",
                "#/real",
                "</href>",
                "</multistatus>"
            ]
        );
        // a foreign empty element is skipped too, and a binding on an empty element does
        // not leak out of it
        let doc = r#"<multistatus xmlns="DAV:"><X:e xmlns:X="urn:other"/><href>/real</href></multistatus>"#;
        assert_eq!(
            events(doc),
            [
                "<multistatus>",
                "<href>",
                "#/real",
                "</href>",
                "</multistatus>"
            ]
        );
        // `xmlns=""` undeclares: the element is in no namespace, which is not DAV:, and
        // the leniency is for a document that declares nothing, not one that declares
        // "nothing" -- the control is the undeclared document two lines down
        let doc = r#"<multistatus xmlns="DAV:"><href xmlns="">/decoy</href><href>/real</href></multistatus>"#;
        assert_eq!(
            events(doc),
            [
                "<multistatus>",
                "<href>",
                "#/real",
                "</href>",
                "</multistatus>"
            ]
        );
        assert_eq!(
            events("<multistatus><href>/a</href></multistatus>"),
            [
                "<multistatus>",
                "<href>",
                "#/a",
                "</href>",
                "</multistatus>"
            ]
        );
        // scoping: an inner default namespace rebinds and unbinds with its element
        let doc = r#"<multistatus xmlns="DAV:"><wrap xmlns="urn:other"><href>/decoy</href></wrap><href>/real</href></multistatus>"#;
        assert_eq!(
            events(doc),
            [
                "<multistatus>",
                "<href>",
                "#/real",
                "</href>",
                "</multistatus>"
            ]
        );
        // the control: a document where every element is DAV: through three different
        // spellings reads every element, so the arm above is not passing by dropping
        // everything with an attribute
        let doc = r#"<D:multistatus xmlns:D="DAV:" xmlns:a="DAV:"><a:response><href xmlns="DAV:">/x</href></a:response></D:multistatus>"#;
        assert_eq!(
            events(doc),
            [
                "<multistatus>",
                "<response>",
                "<href>",
                "#/x",
                "</href>",
                "</response>",
                "</multistatus>"
            ]
        );
        // a namespace URI written with a character reference is the same URI
        assert_eq!(
            events(r#"<D:href xmlns:D="DAV&#58;">/a</D:href>"#),
            ["<href>", "#/a", "</href>"]
        );
        // and `text()` on an element with a foreign child reads around the child
        let mut r = Reader::new(r#"<href xmlns="DAV:">/a<X:b xmlns:X="urn:o">zzz</X:b>/c</href>"#);
        r.next().unwrap();
        assert_eq!(r.text("href").unwrap(), "/a/c");
    }

    #[test]
    fn an_attribute_may_contain_the_character_that_ends_a_tag() {
        // A scanner looking for the next `>` ends the tag inside the attribute and then
        // reads `bar">` as character data. This is the arm for that.
        assert_eq!(
            events(r#"<a x="foo>bar"><b/></a>"#),
            ["<a>", "<b/>", "</a>"]
        );
        assert_eq!(events(r#"<a x='y>z' w="p>q">t</a>"#), ["<a>", "#t", "</a>"]);
        // the control: the same document without the `>` inside the attribute, which the
        // naive scanner also gets right -- so the arm above is measuring the quoting
        assert_eq!(events(r#"<a x="foobar"><b/></a>"#), ["<a>", "<b/>", "</a>"]);
        // and an xmlns whose value holds a `>` is still read as the namespace
        assert_eq!(events(r#"<a xmlns="urn:x>y"><b/></a><c/>"#), ["<c/>"]);
    }

    #[test]
    fn the_five_entities_and_numeric_references_are_decoded_and_nothing_else_is() {
        assert_eq!(decode("a&amp;b&lt;c&gt;d&quot;e&apos;f"), "a&b<c>d\"e'f");
        assert_eq!(decode("&#65;&#x42;&#x1F600;"), "AB\u{1F600}");
        // An entity this reader does not know stays visible rather than vanishing. A
        // dropped character in a filename is a copy that writes to the wrong path and
        // says nothing; a literal `&nbsp;` is wrong in a way somebody notices.
        assert_eq!(decode("a&nbsp;b"), "a&nbsp;b");
        assert_eq!(decode("100% & rising"), "100% & rising");
        assert_eq!(decode("&"), "&");
        assert_eq!(decode("&#xZZ;"), "&#xZZ;");
        // A `;` beyond the window an entity could occupy is not this entity's terminator,
        // and the entity name is bounded. `&#x1F600;` is the longest real form at 10
        // bytes; 13 leaves room and refuses the rest.
        assert_eq!(decode("&thisnameisfartoolong;x"), "&thisnameisfartoolong;x");
        // A multi-byte character sitting where the window ends. `decode` searches BYTES
        // for this reason: the obvious `rest[..13].find(';')` panics here, measured, and
        // a server's reply is enough to reach it.
        assert_eq!(
            decode("&x\u{20AC}\u{20AC}\u{20AC}\u{20AC}\u{20AC}\u{20AC}"),
            "&x\u{20AC}\u{20AC}\u{20AC}\u{20AC}\u{20AC}\u{20AC}"
        );
    }

    /// A `decode` that scans the WHOLE remainder for a `;` before checking that it is close
    /// enough to be an entity costs a full scan per ampersand while advancing one byte.
    /// Measured on a copy of the function: 320 KB took 3.5 s and the cost quadrupled per
    /// doubling, which puts 10 MB at about an hour -- and `decode` runs on every text node,
    /// so one hostile `<D:href>` would hang the PROPFIND walk.
    ///
    /// **IT COUNTS THE SCAN RATHER THAN TIMING IT.** Timing two runs and comparing is not
    /// reliable: it read **24.2** against a bound of 24 on a machine running another suite.
    /// Taking the best of five runs is not enough either -- the same arm read the same 24.2
    /// under three concurrent copies of this suite, because a minimum over five samples only
    /// helps when some sample runs clean, and the LARGE run is precisely the one a loaded
    /// scheduler preempts every time.
    ///
    /// So the instrument changed rather than its statistic. `decode` counts the bytes it
    /// looks at (`scanned`, test builds only), and this compares COUNTS. Exact, identical
    /// on a busy machine and an idle one, and it measures the property the title names --
    /// work per byte of input -- instead of a proxy for it.
    ///
    /// **What that gives up, said plainly:** wall-clock is no longer asserted at all, so a
    /// change that kept the scan linear while making each step expensive would pass. The
    /// trade is taken because the class of defect this guards against -- a full remainder
    /// scan per ampersand -- shows in the count by construction, and because a bound that
    /// needs a quiet machine is not a bound.
    #[test]
    fn decoding_a_run_of_ampersands_is_linear_and_not_quadratic() {
        let work = |s: &str| {
            scanned::reset();
            std::hint::black_box(decode(s));
            scanned::count()
        };
        let small = work(&"&".repeat(20_000));
        let large = work(&"&".repeat(160_000));
        // eight times the input. Linear predicts 8; the quadratic this replaced scans the
        // whole remainder per ampersand, which is 64 at this ratio and grows with it. 24
        // sits between, a third of the way to quadratic and three times linear, so neither
        // class is near the bound.
        let ratio = large as f64 / small as f64;
        assert!(
            ratio < 24.0,
            "decode is superlinear on a run of ampersands: 8x the input looked at {ratio:.1}x as many bytes ({small} -> {large})"
        );
        // Two controls. The counter must MOVE -- a `note_scan` that never fired would make
        // both sides zero and the ratio NaN, which is not `< 24.0`, but say so explicitly
        // rather than relying on that.
        assert!(
            small > 0 && large > 0,
            "the scan counter never moved, so this arm measured nothing"
        );
        // ...and the same measurement on input with no `&` at all, which takes the
        // early-return path. Without it a `decode` that ignored its argument would pass.
        let (a, b) = (work(&"a".repeat(20_000)), work(&"a".repeat(160_000)));
        assert!(
            (b as f64 / a as f64) < 24.0,
            "even the trivial path is superlinear; the measurement is not measuring decode ({a} -> {b})"
        );
    }

    #[test]
    fn a_doctype_is_refused_rather_than_skipped() {
        let mut r = Reader::new(r#"<!DOCTYPE a [<!ENTITY x "boom">]><a>&x;</a>"#);
        let e = r.next().unwrap_err();
        assert!(e.to_string().contains("DOCTYPE"), "{e}");
        // the control: the same document without the DOCTYPE parses, so the refusal is
        // about the DOCTYPE and not about the document being unreadable generally
        assert_eq!(events("<a>b</a>"), ["<a>", "#b", "</a>"]);
    }

    #[test]
    fn resourcetype_is_read_by_the_presence_of_a_child_not_by_text() {
        let mut r = Reader::new("<resourcetype xmlns:D=\"DAV:\"><D:collection/></resourcetype>");
        assert_eq!(
            r.next().unwrap(),
            Some(Event::Start {
                name: "resourcetype",
                empty: false
            })
        );
        assert_eq!(r.child_names("resourcetype").unwrap(), ["collection"]);
        // the control: a file's resourcetype is empty, and must read as no children
        // rather than as an error or as a collection
        let mut r = Reader::new("<resourcetype></resourcetype>");
        r.next().unwrap();
        assert!(r.child_names("resourcetype").unwrap().is_empty());
        // and a `collection` in another namespace is not a collection
        let mut r = Reader::new("<resourcetype><X:collection xmlns:X=\"urn:o\"/></resourcetype>");
        r.next().unwrap();
        assert!(r.child_names("resourcetype").unwrap().is_empty());
    }

    #[test]
    fn text_skips_nested_markup_and_cdata_is_not_decoded() {
        let mut r = Reader::new("<a>x<b>y</b>z</a>");
        r.next().unwrap();
        assert_eq!(r.text("a").unwrap(), "xz");
        let mut r = Reader::new("<a><![CDATA[&amp;<not a tag>]]></a>");
        r.next().unwrap();
        assert_eq!(r.text("a").unwrap(), "&amp;<not a tag>");
    }

    #[test]
    fn an_unterminated_document_is_an_error_and_not_a_silent_truncation() {
        // `<a><b></a></b>` and a mismatched multistatus: tags that do not nest are not a
        // document, and a reader that only counted depth would accept both
        for bad in [
            "<a",
            "<!-- x",
            "<?xml",
            "<![CDATA[x",
            "<a></a",
            "< >",
            "<X:a xmlns:X=\"urn:o\"><b>",
            "</a>",
            "<a><b></a></b>",
            "<multistatus><response><status>HTTP/1.1 200 OK</status></multistatus></response>",
            "<X:a xmlns:X=\"urn:o\"><b></X:b></a>",
        ] {
            let mut r = Reader::new(bad);
            let mut err = false;
            loop {
                match r.next() {
                    Ok(None) => break,
                    Ok(Some(_)) => {}
                    Err(_) => {
                        err = true;
                        break;
                    }
                }
            }
            assert!(err, "{bad:?} was accepted");
        }
    }
}
