//! Separately tuned concurrency for the read stage and the write stage.
//!
//! `-parallel N` is one number for a worker that does both halves of a copy, so it can only
//! express "how many files at once". That is the right knob when the two halves cost the
//! same and neither contends with itself. It is the wrong one whenever they differ --
//! reading from a fast local disk and writing to an object store, or reading from a network
//! share and writing to a device whose throughput PEAKS at a low queue depth and falls off
//! past it. Marlin (Arifuzzaman and Arslan, ICS'23) tunes each stage of a transfer
//! separately for exactly that reason, and a single knob cannot represent a setting where
//! one stage wants more and the other wants fewer.
//!
//! The decomposition here is a pair of counted gates rather than a pair of thread pools.
//! A worker still owns one file end to end; what changes is that it holds a READ permit
//! while the source is producing bytes and a WRITE permit while the sink is taking them,
//! and never both at once. So `read.limit()` caps the threads concurrently inside a read
//! and `write.limit()` caps the threads concurrently inside a write, independently, with
//! no channel between stages, no second buffer copy and no extra threads.
//!
//! **Never both at once is the load-bearing part.** A worker that held its read permit
//! across the write would make the two caps collapse to their minimum -- the gates would
//! still exist, the tuner would still move them, and the numbers would be a fiction.
//! `Stages::write_within_read` is the only sanctioned way to cross the boundary, and it
//! releases before acquiring. `a_worker_never_holds_both_permits` is the arm.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex};

/// A counted gate whose limit may move while holders are inside it.
///
/// Shrinking the limit below the number of holders does not evict anyone -- an I/O in
/// flight runs to completion -- it only makes the next entrant wait. That matters for a
/// tuner: a limit that could cancel work in progress would make every measurement a
/// measurement of cancellation.
pub struct Gate {
    limit: AtomicUsize,
    held: Mutex<usize>,
    room: Condvar,
    /// Every admission ever, cumulative. Unlike `held` it never goes down, so it answers
    /// the question a limit cannot: **was this gate ever entered at all**. A knob whose
    /// setter works over a gate nobody passes through is a knob that does nothing, and it
    /// looks identical from the tuner's log. See
    /// `a_staged_copy_takes_permits_and_a_kernel_copy_does_not`.
    entered: AtomicUsize,
}

impl Gate {
    /// A gate admitting `limit` at once. A limit of zero would admit nobody and deadlock
    /// the run, so it is clamped to one; `set_limit` clamps the same way.
    pub fn new(limit: usize) -> Gate {
        Gate {
            limit: AtomicUsize::new(limit.max(1)),
            held: Mutex::new(0),
            room: Condvar::new(),
            entered: AtomicUsize::new(0),
        }
    }

    pub fn limit(&self) -> usize {
        self.limit.load(Ordering::Relaxed)
    }

    /// Moves the limit and wakes everyone waiting: a raise must admit the waiters it just
    /// made room for, and `notify_one` would admit exactly one however far the limit rose.
    pub fn set_limit(&self, n: usize) {
        self.limit.store(n.max(1), Ordering::Relaxed);
        let _guard = self.held.lock().unwrap();
        self.room.notify_all();
    }

    /// The number of holders inside right now. For the tuner's log and for tests; a
    /// decision made on it would be racing by the time it was read.
    pub fn held(&self) -> usize {
        *self.held.lock().unwrap()
    }

    /// How many times this gate has been entered since it was made.
    pub fn entered(&self) -> usize {
        self.entered.load(Ordering::Relaxed)
    }

    /// Waits for room, then takes it until the returned permit drops.
    pub fn enter(&self) -> Permit<'_> {
        let mut held = self.held.lock().unwrap();
        while *held >= self.limit.load(Ordering::Relaxed) {
            held = self.room.wait(held).unwrap();
        }
        *held += 1;
        self.entered.fetch_add(1, Ordering::Relaxed);
        Permit { gate: self }
    }
}

/// Room inside a gate, given back when it drops.
pub struct Permit<'a> {
    gate: &'a Gate,
}

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        let mut held = self.gate.held.lock().unwrap();
        *held -= 1;
        self.gate.room.notify_one();
    }
}

/// The two gates a copy passes through.
pub struct Stages {
    pub read: Gate,
    pub write: Gate,
    /// The most either gate may be raised to. Both start below it so the tuner has room to
    /// move in either direction from the first window.
    pub ceiling: usize,
}

impl std::fmt::Debug for Stages {
    /// The limits, not the occupancy: `held` takes a lock, and a `Debug` that blocks is a
    /// `Debug` that can deadlock whatever it is printed from.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Stages {{ read: {}, write: {}, ceiling: {} }}",
            self.read.limit(),
            self.write.limit(),
            self.ceiling
        )
    }
}

impl Stages {
    pub fn new(ceiling: usize) -> Stages {
        let start = ceiling.clamp(1, 2);
        Stages {
            read: Gate::new(start),
            write: Gate::new(start),
            ceiling: ceiling.max(1),
        }
    }

    /// Runs `f` under a write permit, having first given back the read permit `held` and
    /// taken it again afterwards.
    ///
    /// This is called from inside the source's read callback, which is the one place where
    /// a thread would otherwise hold both. The read permit goes back FIRST so the two are
    /// never held together; the cost is that the worker re-queues for the read gate on
    /// every block, which is the mechanism rather than an overhead to be optimized away --
    /// it is what makes a read limit of 2 mean two threads reading.
    pub fn write_within_read<'a, T>(
        &'a self,
        held: &mut Option<Permit<'a>>,
        f: impl FnOnce() -> T,
    ) -> T {
        let had = held.take().is_some();
        let out = {
            let _w = self.write.enter();
            f()
        };
        if had {
            // Re-acquire even when the gate is now full: a worker that skipped it would be
            // reading unmetered from here on, and the read limit would stop meaning
            // anything for the rest of the file.
            *held = Some(self.read.enter());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    #[test]
    fn a_gate_admits_its_limit_and_no_more() {
        let gate = Arc::new(Gate::new(3));
        let peak = Arc::new(AtomicUsize::new(0));
        let inside = Arc::new(AtomicUsize::new(0));
        std::thread::scope(|s| {
            for _ in 0..12 {
                let (gate, peak, inside) =
                    (Arc::clone(&gate), Arc::clone(&peak), Arc::clone(&inside));
                s.spawn(move || {
                    for _ in 0..40 {
                        let _p = gate.enter();
                        let now = inside.fetch_add(1, Ordering::SeqCst) + 1;
                        peak.fetch_max(now, Ordering::SeqCst);
                        std::thread::sleep(Duration::from_micros(200));
                        inside.fetch_sub(1, Ordering::SeqCst);
                    }
                });
            }
        });
        assert_eq!(
            inside.load(Ordering::SeqCst),
            0,
            "a permit was not given back"
        );
        assert_eq!(
            peak.load(Ordering::SeqCst),
            3,
            "peak occupancy was {}, limit is 3",
            peak.load(Ordering::SeqCst)
        );

        // The control, and it is what makes the line above mean anything: the SAME workload
        // through a wide gate must actually reach more than 3 at once. Without it, a
        // scheduler that simply never overlapped these threads would pass the assertion
        // with the gate doing no work at all.
        let gate = Arc::new(Gate::new(12));
        let peak = Arc::new(AtomicUsize::new(0));
        let inside = Arc::new(AtomicUsize::new(0));
        std::thread::scope(|s| {
            for _ in 0..12 {
                let (gate, peak, inside) =
                    (Arc::clone(&gate), Arc::clone(&peak), Arc::clone(&inside));
                s.spawn(move || {
                    for _ in 0..40 {
                        let _p = gate.enter();
                        let now = inside.fetch_add(1, Ordering::SeqCst) + 1;
                        peak.fetch_max(now, Ordering::SeqCst);
                        std::thread::sleep(Duration::from_micros(200));
                        inside.fetch_sub(1, Ordering::SeqCst);
                    }
                });
            }
        });
        assert!(
            peak.load(Ordering::SeqCst) > 3,
            "the wide control peaked at {}, so the narrow arm proved nothing",
            peak.load(Ordering::SeqCst)
        );
    }

    #[test]
    fn raising_the_limit_wakes_everyone_it_made_room_for() {
        let gate = Arc::new(Gate::new(1));
        let entered = Arc::new(AtomicUsize::new(0));
        let go = Arc::new(AtomicBool::new(false));
        std::thread::scope(|s| {
            let held = gate.enter();
            for _ in 0..4 {
                let (gate, entered, go) =
                    (Arc::clone(&gate), Arc::clone(&entered), Arc::clone(&go));
                s.spawn(move || {
                    while !go.load(Ordering::SeqCst) {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    let _p = gate.enter();
                    entered.fetch_add(1, Ordering::SeqCst);
                    std::thread::sleep(Duration::from_millis(80));
                });
            }
            go.store(true, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(30));
            assert_eq!(
                entered.load(Ordering::SeqCst),
                0,
                "a waiter got in while the only slot was held"
            );

            // one raise, to 5, must admit all four at once -- notify_one would admit one
            gate.set_limit(5);
            let deadline = Instant::now() + Duration::from_secs(5);
            while entered.load(Ordering::SeqCst) < 4 && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(2));
            }
            assert_eq!(
                entered.load(Ordering::SeqCst),
                4,
                "only {} of 4 waiters woke on one raise",
                entered.load(Ordering::SeqCst)
            );
            drop(held);
        });
    }

    #[test]
    fn shrinking_the_limit_lets_the_holders_finish() {
        let gate = Arc::new(Gate::new(4));
        let a = gate.enter();
        let b = gate.enter();
        let c = gate.enter();
        assert_eq!(gate.held(), 3);
        gate.set_limit(1);
        // nobody is evicted
        assert_eq!(gate.held(), 3, "shrinking the limit dropped a holder");
        drop(a);
        drop(b);
        assert_eq!(gate.held(), 1);
        // and the new limit is now in force for an entrant
        let entered = Arc::new(AtomicBool::new(false));
        std::thread::scope(|s| {
            let (g, e) = (Arc::clone(&gate), Arc::clone(&entered));
            s.spawn(move || {
                let _p = g.enter();
                e.store(true, Ordering::SeqCst);
            });
            std::thread::sleep(Duration::from_millis(40));
            assert!(
                !entered.load(Ordering::SeqCst),
                "the shrunk limit admitted an entrant over it"
            );
            drop(c);
        });
        assert!(
            entered.load(Ordering::SeqCst),
            "the entrant never got in after the holder left"
        );
    }

    #[test]
    fn a_limit_of_zero_is_clamped_rather_than_deadlocking() {
        let gate = Gate::new(0);
        assert_eq!(gate.limit(), 1);
        gate.set_limit(0);
        assert_eq!(gate.limit(), 1);
        let _p = gate.enter(); // would hang forever if the clamp were missing
    }

    #[test]
    fn a_worker_never_holds_both_permits() {
        // The property the whole decomposition rests on. A reader that kept its permit
        // across the write would make the two limits collapse into one, and every number
        // the tuner reported would be about a knob that did nothing.
        //
        // The shape of the arm is what makes it falsifiable. A narrow READ gate and a wide
        // WRITE gate: if the read permit really is handed back before the write, several
        // threads can be writing at once even though only one may be reading, so the write
        // gate's peak occupancy exceeds one. If it were held across the write, only the
        // single read-permit holder could ever reach a write, and that peak would be
        // pinned at exactly one however wide the write gate was.
        //
        // Replanted to check it fires: with `held.take()` moved to AFTER `self.write.enter()`
        // in `write_within_read` -- the whole defect, and the only way to write it -- this
        // arm fails with "the write gate peaked at 1".
        let stages = Stages::new(8);
        stages.read.set_limit(1);
        stages.write.set_limit(4);
        let peak = AtomicUsize::new(0);
        let inside_write = AtomicUsize::new(0);
        std::thread::scope(|s| {
            for _ in 0..4 {
                let (stages, peak, inside_write) = (&stages, &peak, &inside_write);
                s.spawn(move || {
                    for _ in 0..60 {
                        let mut held = Some(stages.read.enter());
                        stages.write_within_read(&mut held, || {
                            let now = inside_write.fetch_add(1, Ordering::SeqCst) + 1;
                            peak.fetch_max(now, Ordering::SeqCst);
                            std::thread::sleep(Duration::from_micros(300));
                            inside_write.fetch_sub(1, Ordering::SeqCst);
                        });
                        assert!(
                            held.is_some(),
                            "the read permit was not given back after the write"
                        );
                    }
                });
            }
        });
        assert_eq!(inside_write.load(Ordering::SeqCst), 0);
        assert!(
            peak.load(Ordering::SeqCst) > 1,
            "the write gate peaked at {} with a read limit of 1: the read permit is being held across the write, so the two limits are one limit",
            peak.load(Ordering::SeqCst)
        );
    }

    #[test]
    fn write_within_read_returns_the_permit_it_was_given_and_no_other() {
        let stages = Stages::new(4);
        stages.read.set_limit(1);
        let mut held = Some(stages.read.enter());
        assert_eq!(stages.read.held(), 1);
        let out = stages.write_within_read(&mut held, || 7);
        assert_eq!(out, 7);
        assert!(held.is_some());
        assert_eq!(
            stages.read.held(),
            1,
            "the read gate holds {} after a round trip",
            stages.read.held()
        );

        // and the control: with no permit in hand it must not invent one, or a worker on a
        // path that never took a read permit would leak occupancy into the read gate
        let mut none: Option<Permit<'_>> = None;
        stages.write_within_read(&mut none, || {});
        assert!(
            none.is_none(),
            "write_within_read handed back a permit it was never given"
        );
        drop(held);
        assert_eq!(stages.read.held(), 0);
    }

    #[test]
    fn the_stages_start_below_the_ceiling_so_the_tuner_can_move_either_way() {
        let s = Stages::new(16);
        assert_eq!((s.read.limit(), s.write.limit()), (2, 2));
        assert_eq!(s.ceiling, 16);
        // a one-worker run has nowhere to go up, and must still be legal
        let s = Stages::new(1);
        assert_eq!((s.read.limit(), s.write.limit(), s.ceiling), (1, 1, 1));
    }
}
