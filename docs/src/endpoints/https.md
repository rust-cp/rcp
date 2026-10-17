# Web servers as sources: https:// and http://

```
rcp copy https://mirror.example/pub/dataset /data/dataset
rcp copy -http.index '' https://mirror.example/pub /data/pub   # ignore any index; use the autoindex
```

A read-only tree, and the refusal is the interesting half: `copy` INTO one, `sync`, `delete`
and `chmod` all fail by name rather than issuing a `PUT` that some servers accept and
others do not. A plain web server has no agreed way to create anything; the protocol that
does is `dav://`, which is already here.

**HTTP has no directory listing.** What it has is three conventions, and which one you get
is decided by an operator you do not control, so all three are read, in order of how much
truth they carry:

| shape | what it carries | cost |
| --- | --- | --- |
| `rcp-index.json` | path, kind, size, mtime, mode and digest | ONE request for the whole tree |
| nginx `autoindex_format json` | name, kind, size, the server's date | one request per directory |
| Apache-style HTML | names, and a trailing `/` for a directory | a request per directory plus a `HEAD` per file |

The first is this crate's own: `rcp scan -json > rcp-index.json` at the tree root, published
beside the files, needs no post-processing — the reader takes the newline-delimited stream
the scan writes, `done` event and all. It is the only shape that carries the source's own
mtime, so it is the only one for which `keeps_times` is true; against the other two the
planner matches on size and `verify` skips the mtime comparison and says so.

**The HTML reader is where the judgement is**, because an autoindex page is mostly links
that are not files, and turning one into a file is how a copy acquires something called
`?C=N;O=D`. Four kinds are dropped and each has its own reason: a link with a query or
fragment is a control (a real `?` in a name arrives as `%3F`, so cutting on the literal
loses nothing); a link that leaves the directory is navigation, which is what Apache's
"Parent Directory" is and what makes a naive walker climb out; a link equal to the
directory is the self-link, the same trap WebDAV's own `PROPFIND` entry sets; and a
duplicate is Apache emitting the icon link and the text link for one entry.

The contract arm serves ONE fixture all three ways and compares the three results **against
each other** as well as against the source. That is the arm that a shared omission cannot
pass: a bug dropping the same file from all three would satisfy any per-shape assertion.

One limit is worth stating rather than discovering: **no command drives a seek on a source
reader**, so the `Range` path here is measured by unit arms that seek the reader directly,
as the registry and WebDAV readers are. `diag nio` is the one core caller of `Seek` and it
lays out its own files with `create_file`, so it needs a writable tree and can never be a
read-only endpoint's benchmark.
