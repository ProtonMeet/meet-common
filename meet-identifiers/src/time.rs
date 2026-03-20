#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum TimeArg {
    /// Durating elapsed since UNIX_EPOCH
    Absolute(core::time::Duration),
    /// Duration from now
    Relative(core::time::Duration),
}

impl TimeArg {
    #[allow(clippy::wrong_self_convention)]
    pub(crate) fn to_absolute(&self, now: core::time::Duration) -> core::time::Duration {
        match *self {
            Self::Absolute(d) => d,
            Self::Relative(d) => now + d,
        }
    }
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub fn elapsed_since_epoch() -> core::time::Duration {
    let js_date = js_sys::Date::new_0();
    let timestamp_millis = js_date.get_time() as u64;
    std::time::Duration::from_millis(timestamp_millis)
}

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub fn elapsed_since_epoch() -> core::time::Duration {
    let now = std::time::SystemTime::now();
    now.duration_since(std::time::SystemTime::UNIX_EPOCH)
        .expect("System clock is before UNIX_EPOCH")
}
