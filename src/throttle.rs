//! `-bwlimit`: a token bucket behind the `Throttle` port, shared by every worker and engine
//! through the `Runtime`, so the limit is the run's total rate whatever the parallelism.
//! The bucket runs a debt: a read takes its bytes at once and sleeps off whatever it
//! overdrew, which keeps the average exact without splitting reads. Refill is capped at
//! one second of the rate, so a pause does not bank a burst.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::ports::Throttle;

pub struct TokenBucket {
    rate: f64,
    state: Mutex<(f64, Instant)>,
}

impl TokenBucket {
    pub fn new(bytes_per_second: u64) -> TokenBucket {
        TokenBucket {
            rate: bytes_per_second as f64,
            state: Mutex::new((0.0, Instant::now())),
        }
    }
    pub fn rate(&self) -> u64 {
        self.rate as u64
    }
}

impl Throttle for TokenBucket {
    fn take(&self, bytes: u64) {
        if bytes == 0 {
            return;
        }
        let debt = {
            let mut s = self.state.lock().unwrap();
            let now = Instant::now();
            let refill = now.duration_since(s.1).as_secs_f64() * self.rate;
            s.0 = (s.0 + refill).min(self.rate);
            s.1 = now;
            s.0 -= bytes as f64;
            -s.0
        };
        if debt > 0.0 {
            std::thread::sleep(Duration::from_secs_f64(debt / self.rate));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **The two bounds here are not the same kind of claim, and only one of them can be
    /// tight.** The property is that the bucket WAITS, so the lower bound is the assertion
    /// and it is robust by construction: a loaded machine only ever makes a sleep longer,
    /// never shorter, so no amount of contention can push `took` below the debt.
    ///
    /// The upper bound is a different thing -- a sanity check that the rate is not off by
    /// an order of magnitude -- and a TIGHT upper bound on elapsed time is a measurement of
    /// the machine, which is the defect class that took `dav/xml.rs` and `transfer.rs` two
    /// commits each on 2026-09-24. So it is deliberately loose: 6 MiB at 4 MiB/s is 1.5 s,
    /// a rate wrong by 10x would be 15 s, and 10 s sits between with room on both sides.
    #[test]
    fn a_bucket_meters_bytes_at_its_rate() {
        // 4 MiB/s, 6 MiB taken in 1 MiB reads, which must take at least the debt beyond
        // the first second's allowance
        let b = TokenBucket::new(4 << 20);
        let start = Instant::now();
        for _ in 0..6 {
            b.take(1 << 20);
        }
        let took = start.elapsed().as_secs_f64();
        assert!(
            took >= 1.4,
            "6 MiB at 4 MiB/s from an empty bucket takes 1.5 s, took {took:.2}"
        );
        assert!(took < 10.0, "6 MiB at 4 MiB/s should take about 1.5 s; a rate wrong by 10x would take 15 s. Took {took:.2}");
        assert_eq!(b.rate(), 4 << 20);
        // The control: the null throttle never waits. 250 ms rather than the 50 ms this
        // used to allow, for the same reason as above -- the claim is "does not sleep for
        // a second and a half", and 250 ms says that with six times the margin while
        // leaving no room for a throttle that actually waits.
        let start = Instant::now();
        crate::ports::Unlimited.take(1 << 30);
        assert!(
            start.elapsed() < Duration::from_millis(250),
            "the null throttle waited; it is not null"
        );
    }
}
