# platform-info

[![Crates.io](https://img.shields.io/crates/v/platform-info.svg)](https://crates.io/crates/platform-info)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CodeCov](https://codecov.io/gh/uutils/platform-info/branch/main/graph/badge.svg)](https://codecov.io/gh/uutils/platform-info/tree/main)

A simple cross-platform way to get information about the currently running system.

## Example

This simple example:

```rust
// examples/ex.rs
// * use `cargo run --example ex` to execute this example

use platform_info::*;

fn main() {
    let uname = PlatformInfo::new().unwrap();
    println!("{}", (uname.sysname()).unwrap_or_else(|os_s| os_s.to_string_lossy()));
    println!("{}", (uname.nodename()).unwrap_or_else(|os_s| os_s.to_string_lossy()));
    println!("{}", (uname.release()).unwrap_or_else(|os_s| os_s.to_string_lossy()));
    println!("{}", (uname.version()).unwrap_or_else(|os_s| os_s.to_string_lossy()));
    println!("{}", (uname.machine()).unwrap_or_else(|os_s| os_s.to_string_lossy()));
    println!("{}", (uname.osname()).unwrap_or_else(|os_s| os_s.to_string_lossy()));
}
```

should display something like:

```text
Linux
hostname
5.10.0-8-amd64
#1 SMP Debian 5.10.46-4 (2021-08-03)
x86_64
GNU/Linux
```

> Using `cargo run --example ex` will execute this [example code](examples/ex.rs).

## License

`platform-info` is licensed under the MIT License - see the LICENSE file for details.
