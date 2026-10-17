# Cluster mode

`rcp copy -nodes w0,w1,w2 SOURCE DESTINATION` spreads a copy over a worker fleet: the coordinator
(this process) lists and plans as usual, then hands the file batches, balanced by size, to
`rcp copybatch` workers started over `ssh` on each node and collects one result line per
file. Directories, hard links, symlinks, metadata and the catalog stay with the coordinator,
so `resume -id` and `sync -id` work on a fleet-made copy exactly as on a local one. A node
needs `rcp` on its `PATH` and the same endpoints reachable: an export or a bucket is shared
by nature, a local path has to be the same mount everywhere. `localhost` as a node name runs
a worker on this host without ssh, and `RCP_SSH` names the ssh program. `scan -nodes` lists
the top level here and one top-level subtree per worker, merging the entries. `resume` and
`sync` take `-nodes` too.

`-copybatch 'PROG ARGS'` runs a program of yours instead of `rcp copybatch` on every node
(or here, without `-nodes`), as a line protocol: the program gets `SOURCE DESTINATION` appended to its
arguments, NUL-separated paths relative to the source on stdin, and prints one line per
path, `ok<TAB>PATH<TAB>BYTES<TAB>SHA256-or-empty<TAB>OWNER-REFUSED<TAB>XATTRS-REFUSED` or
`fail<TAB>PATH<TAB>MESSAGE`. A path with no line, or a worker that dies, is a failure for
every file it was given; the coordinator never guesses.
