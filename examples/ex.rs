// examples/ex.rs
// * use `cargo run --example ex` to execute this example

// spell-checker:ignore (API) nodename osname sysname

use platform_info::*;

fn main() {
    let uname = PlatformInfo::new().unwrap();

    println!(
        "{}",
        (uname.sysname()).unwrap_or_else(|os_s| os_s.to_string_lossy())
    );
    println!(
        "{}",
        (uname.nodename()).unwrap_or_else(|os_s| os_s.to_string_lossy())
    );
    println!(
        "{}",
        (uname.release()).unwrap_or_else(|os_s| os_s.to_string_lossy())
    );
    println!(
        "{}",
        (uname.version()).unwrap_or_else(|os_s| os_s.to_string_lossy())
    );
    println!(
        "{}",
        (uname.machine()).unwrap_or_else(|os_s| os_s.to_string_lossy())
    );
    println!(
        "{}",
        (uname.osname()).unwrap_or_else(|os_s| os_s.to_string_lossy())
    );
}
