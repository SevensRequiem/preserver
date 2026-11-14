use std::sync::Mutex;
use std::time::{Duration, Instant};

const BURST: f64 = 256.0 * 1024.0;

/// One token bucket shared by every download stream and proxy tunnel.
pub(crate) struct Throttle {
    /// Bytes per second; 0 means no limit.
    rate: f64,
    bucket: Mutex<(f64, Instant)>,
}

impl Throttle {
    pub(crate) fn new(bytes_per_sec: u64) -> Self {
        #[expect(
            clippy::cast_precision_loss,
            reason = "a rate, exact far beyond any link"
        )]
        let rate = bytes_per_sec as f64;
        Self {
            rate,
            bucket: Mutex::new((0.0, Instant::now())),
        }
    }

    pub(crate) fn from_mbit(mbit: u32) -> Self {
        Self::new(u64::from(mbit) * 125_000)
    }

    pub(crate) fn bytes_per_sec(&self) -> f64 {
        self.rate
    }

    /// Charges `n` bytes. Tokens may go negative, so concurrent streams queue behind each
    /// other's debt and each caller sleeps off only its own share.
    pub(crate) fn take(&self, n: usize) {
        if self.rate == 0.0 {
            return;
        }
        let wait = {
            let mut b = self
                .bucket
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let now = Instant::now();
            #[expect(clippy::cast_precision_loss, reason = "a chunk size")]
            let n = n as f64;
            b.0 = (b.0 + now.duration_since(b.1).as_secs_f64() * self.rate).min(BURST) - n;
            b.1 = now;
            (b.0 < 0.0).then(|| Duration::from_secs_f64(-b.0 / self.rate))
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
}
