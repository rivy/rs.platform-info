// examples/arch.rs
// * use `cargo run --example arch` to execute this example

// spell-checker:ignore (API) nodename osname sysname

use platform_info::*;

fn main() {
    let info = PlatformInfo::new().unwrap_or_else(|err| {
        // using debug formatting ("{:?}") to display the full error stack
        eprintln!("Unable to determine platform info: {:?}", err);
        std::process::exit(1);
    });
    println!(
        "{}",
        match info.machine().to_os_string().into_string() {
            Ok(s) => s,
            Err(os_s) => {
                let s = os_s.to_string_lossy();
                eprintln!("machine = [{}]'{:?}' => '{}'", os_s.len(), os_s, s);
                String::from(s)
            }
        }
    );
}
