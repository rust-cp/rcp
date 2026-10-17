# Container evidence

The raw reports from the 2026-10-01 image inspection are not in the tree.
They were local scan output: an SBOM, a vulnerability report, and smoke
logs. One of those reports embedded a workstation path. History was
rewritten on 2026-10-16 to remove that path. A clone of the rewritten
history does not contain it.

What the inspection established:

- The release binary's maximum required glibc symbol is 2.29. The runtime
  under test provides 2.34. v0.1.0 required glibc 2.39 and does not run there.
- The hardened image smoke covered 13 cases: numeric user 10001, no
  capabilities, `no_new_privileges`, seccomp, a read-only root, GSSAPI, ssh
  startup with no shell, copy of content, mode, and mtime, a changed sync,
  MCP, and deletion confirmation.
- The vulnerability scan of that image reported 14 matches against Ubuntu
  vendor data: 13 Medium and one Negligible. Thirteen were `not-fixed` and
  one was `wont-fix`. No ignore file was added. The retained packages were
  zlib, PCRE2, and glibc, including advisories whose CVSS scores are High
  even where Ubuntu's priority is lower. Those are retained vendor risks,
  not a claim that the image has no vulnerabilities.
- An earlier scan of the same image omitted source-package fields and
  reported no matches. That scan is incomplete and is not a substitute for
  the counts above.

CI still builds the image and writes a fresh SBOM and vulnerability report
into the job's temporary directory. Those artifacts are not committed.
