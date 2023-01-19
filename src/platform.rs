#[cfg(unix)]
#[path = "platform/unix.rs"]
mod target;
#[cfg(windows)]
#[path = "platform/windows.rs"]
mod target;
#[cfg(not(any(unix, windows)))]
#[path = "platform/unknown.rs"]
mod target;
pub use self::target::*;
