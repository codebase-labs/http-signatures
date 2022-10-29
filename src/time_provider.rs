use std::fmt::Debug;
use std::time::SystemTime;

/// An abstraction over system time. Intended to allow consumers to provide a
/// different implementation that is supported on their platform.
pub trait TimeProvider: Debug + Sync + 'static {
    /// The number of seconds since the Unix epoch.
    fn unix_timestamp(&self) -> i64;
}

/// Implemented in terms of `std::time::SystemTime`.
#[derive(Debug, Copy, Clone)]
pub struct DefaultTimeProvider;

impl TimeProvider for DefaultTimeProvider {
    fn unix_timestamp(&self) -> i64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("Unix time to be positive")
            .as_secs() as i64
    }
}
