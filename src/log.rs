//! `-loglevel DEBUG`: the stderr adapter behind the `Log` port, one line per event at the
//! seams where a run can go wrong (an endpoint opened, a server's ports and programs, a
//! request and its status, a worker launched), on stderr so the report on stdout stays the
//! report. `INFO`, the default, is the port's `Silent` adapter.

use std::fmt;
use std::io::Write;

use crate::ports::Log;

/// Debug lines on stderr.
pub struct Stderr;

impl Log for Stderr {
    fn enabled(&self) -> bool {
        true
    }
    fn line(&self, args: fmt::Arguments<'_>) {
        let stderr = std::io::stderr();
        let mut out = stderr.lock();
        let _ = writeln!(out, "DEBUG {args}");
    }
}
