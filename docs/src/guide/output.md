# Exit codes and output are the contract

Wrappers can rely on three things: the exit code, the final `STATUS:` line, and `ERROR:` lines.
rcp never prints `STATUS: FAILED` while exiting 0. The integration tests in
`tests/contract.rs` pin this, and every arm that shows a check passing has a control arm that
plants the defect and requires the check to fail. Sockets, FIFOs and device nodes are skipped with
a `WARN:` line. A copy that fails on some entries still copies the rest, reports each failure,
exits 1 and keeps its catalog, so `resume` can finish the job.
