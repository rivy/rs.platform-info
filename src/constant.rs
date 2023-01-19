// private platform-specific HOST_OS_NAME * ref: [`uname` info](https://en.wikipedia.org/wiki/Uname)
#[cfg(all(target_os = "linux", any(target_env = "gnu", target_env = "")))]
const HOST_OS_NAME: &str = "GNU/Linux";
#[cfg(all(target_os = "linux", not(any(target_env = "gnu", target_env = ""))))]
const HOST_OS_NAME: &str = "Linux";
#[cfg(target_os = "android")]
const HOST_OS_NAME: &str = "Android";
#[cfg(target_os = "windows")]
pub const HOST_OS_NAME: &str = "MS/Windows"; // prior art == `busybox`
#[cfg(target_os = "freebsd")]
const HOST_OS_NAME: &str = "FreeBSD";
#[cfg(target_os = "netbsd")]
const HOST_OS_NAME: &str = "NetBSD";
#[cfg(target_os = "openbsd")]
const HOST_OS_NAME: &str = "OpenBSD";
#[cfg(target_vendor = "apple")]
const HOST_OS_NAME: &str = "Darwin";
#[cfg(target_os = "fuchsia")]
const HOST_OS_NAME: &str = "Fuchsia";
#[cfg(target_os = "redox")]
const HOST_OS_NAME: &str = "Redox";
