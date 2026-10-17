# The catalog

One directory per copy ID, at `-catalog DIR`, else `$RCP_CATALOG`, else
`$XDG_STATE_HOME/rcp/catalog`, else `~/.local/state/rcp/catalog`. Inside, `index.tsv` starts with
the two endpoints and then holds one tab-separated line per completed entry: path, kind, size,
mtime (ns), mode, uid, gid, SHA-256, source inode (the column `sync` uses to recognize a
renamed file; catalogs written without it still read). Lines are appended and flushed as entries complete, so a copy
killed part-way leaves a truthful index. A copy ID that already exists is refused: two copies must
never share a resume record. `jobs.log` beside the catalogs records every command.
