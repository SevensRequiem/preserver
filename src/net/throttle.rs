use std::sync::Mutex;
use std::time::{Duration, Instant};

const BURST: f64 = 256.0 * 1024.0;

/// One token bucket shared by every download stream and proxy tunnel. The rate can change
/// while streams run.
pub(crate) struct Throttle {
    bucket: Mutex<Bucket>,
}

struct Bucket {
    /// Bytes per second; 0 means no limit.
    rate: f64,
    tokens: f64,
    at: Instant,
}

fn refill(b: &mut Bucket, now: Instant) {
    b.tokens = (b.tokens + now.duration_since(b.at).as_secs_f64() * b.rate).min(BURST);
    b.at = now;
}

impl Throttle {
    pub(crate) fn new(bytes_per_sec: u64) -> Self {
        #[expect(
            clippy::cast_precision_loss,
            reason = "a rate, exact far beyond any link"
        )]
        let rate = bytes_per_sec as f64;
        Self {
            bucket: Mutex::new(Bucket {
                rate,
                tokens: 0.0,
                at: Instant::now(),
            }),
        }
    }

    pub(crate) fn from_mbit(mbit: u32) -> Self {
        Self::new(u64::from(mbit) * 125_000)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Bucket> {
        self.bucket
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(crate) fn bytes_per_sec(&self) -> f64 {
        self.lock().rate
    }

    /// Switches the rate; false when it is already that. Debt carries over in bytes and is paid
    /// at the new rate. Unlimited time was never charged, so a switch to or from 0 starts empty.
    pub(crate) fn set_mbit(&self, mbit: u32) -> bool {
        #[expect(
            clippy::cast_precision_loss,
            reason = "a rate, exact far beyond any link"
        )]
        let rate = (u64::from(mbit) * 125_000) as f64;
        let mut b = self.lock();
        #[expect(clippy::float_cmp, reason = "both come from whole Mbit/s")]
        if b.rate == rate {
            return false;
        }
        let now = Instant::now();
        if b.rate == 0.0 || rate == 0.0 {
            b.tokens = 0.0;
            b.at = now;
        } else {
            refill(&mut b, now);
        }
        b.rate = rate;
        true
    }

    /// Charges `n` bytes. Tokens may go negative, so concurrent streams queue behind each
    /// other's debt and each caller sleeps off only its own share.
    pub(crate) fn take(&self, n: usize) {
        let wait = {
            let mut b = self.lock();
            if b.rate == 0.0 {
                return;
            }
            refill(&mut b, Instant::now());
            #[expect(clippy::cast_precision_loss, reason = "a chunk size")]
            let n = n as f64;
            b.tokens -= n;
            (b.tokens < 0.0).then(|| Duration::from_secs_f64(-b.tokens / b.rate))
        };
        if let Some(wait) = wait {
            std::thread::sleep(wait);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_bucket_holds_the_rate_across_threads() {
        let t = Throttle::new(4 << 20);
        let start = Instant::now();
        std::thread::scope(|s| {
            for _ in 0..4 {
                s.spawn(|| {
                    for _ in 0..32 {
                        t.take(16 << 10);
                    }
                });
            }
        });
        // 2 MiB at 4 MiB/s: 0.5 s, whatever the split between threads.
        let secs = start.elapsed().as_secs_f64();
        assert!((0.45..0.6).contains(&secs), "{secs}");
    }

    #[test]
    fn zero_is_unlimited() {
        let t = Throttle::from_mbit(0);
        let start = Instant::now();
        t.take(1 << 30);
        assert!(start.elapsed() < Duration::from_millis(50));
    }

    #[test]
    fn set_mbit_keeps_debt_across_rate_changes() {
        for (to, changed, zero) in [(16, true, false), (8, false, false), (0, true, true)] {
            let t = Throttle::from_mbit(8);
            t.bucket.lock().unwrap().tokens = -(64.0 * 1024.0);
            let at = t.bucket.lock().unwrap().at;
            std::thread::sleep(Duration::from_millis(20));
            assert_eq!(t.set_mbit(to), changed, "to {to}");
            let b = t.bucket.lock().unwrap();
            if zero {
                assert!(b.tokens == 0.0, "to {to}");
            } else if changed {
                let want = -(64.0 * 1024.0) + b.at.duration_since(at).as_secs_f64() * 1_000_000.0;
                assert!((b.tokens - want).abs() < 1024.0, "to {to}: {}", b.tokens);
            } else {
                assert!(b.at == at, "to {to}");
            }
        }
        let t = Throttle::from_mbit(0);
        assert!(t.set_mbit(8));
        let b = t.bucket.lock().unwrap();
        assert!(b.tokens == 0.0 && b.at.elapsed() < Duration::from_millis(50));
    }

    #[test]
    fn a_rate_change_mid_stream_applies_to_later_takes() {
        let t = Throttle::from_mbit(32);
        let start = Instant::now();
        std::thread::scope(|s| {
            for _ in 0..4 {
                s.spawn(|| {
                    for _ in 0..32 {
                        t.take(16 << 10);
                    }
                });
            }
            std::thread::sleep(Duration::from_millis(250));
            t.set_mbit(64);
        });
        // 2 MiB: 1 MB in the first 250 ms at 4 MB/s, the rest at 8 MB/s.
        let secs = start.elapsed().as_secs_f64();
        assert!((0.33..0.5).contains(&secs), "{secs}");
    }

    #[test]
    fn switching_to_unlimited_stops_charging() {
        let t = Throttle::from_mbit(1);
        t.set_mbit(0);
        let start = Instant::now();
        t.take(1 << 30);
        assert!(start.elapsed() < Duration::from_millis(50));
    }
}
