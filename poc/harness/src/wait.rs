use std::thread;
use std::time::{Duration, Instant};

/// Check immediately, then poll local readiness every 20 ms until the deadline.
/// Returns elapsed time on success or timeout.
pub fn until(deadline: Instant, mut ready: impl FnMut() -> bool) -> Result<Duration, Duration> {
    let start = Instant::now();
    loop {
        if ready() {
            return Ok(start.elapsed());
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(start.elapsed());
        }
        thread::sleep(remaining.min(Duration::from_millis(20)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checks_immediately_even_when_deadline_has_passed() {
        let mut checks = 0;
        let result = until(Instant::now(), || {
            checks += 1;
            true
        });
        assert!(result.is_ok());
        assert_eq!(checks, 1);
    }

    #[test]
    fn timeout_is_bounded() {
        let start = Instant::now();
        assert!(until(start + Duration::from_millis(25), || false).is_err());
        assert!(start.elapsed() < Duration::from_millis(100));
    }
}
