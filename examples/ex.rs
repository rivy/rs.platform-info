// `cargo run --example ex` (executes this example)

use platform_info::*;

fn main() {
    let uname = PlatformInfo::new().unwrap();
    println!("{}", uname.sysname().to_string_lossy());
    println!("{}", uname.nodename().to_string_lossy());
    println!("{}", uname.release().to_string_lossy());
    println!("{}", uname.version().to_string_lossy());
    println!("{}", uname.machine().to_string_lossy());
    println!("{}", uname.osname().to_string_lossy());
}
