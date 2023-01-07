// This file is part of the uutils coreutils package.
//
// (c) Ingvar Stepanyan <me@rreverser.com>
//
// For the full copyright and license information, please view the LICENSE file
// that was distributed with this source code.
//

use super::Uname;
use std::borrow::Cow;

pub struct PlatformInfo(());

impl PlatformInfo {
    pub fn new() -> std::io::Result<Self> {
        Ok(Self(()))
    }
}

impl Uname for PlatformInfo {
    fn sysname(&self) -> Cow<str> {
        Cow::Borrowed("unknown")
    }

    fn nodename(&self) -> Cow<str> {
        Cow::Borrowed("unknown")
    }

    fn release(&self) -> Cow<str> {
        Cow::Borrowed("unknown")
    }

    fn version(&self) -> Cow<str> {
        Cow::Borrowed("unknown")
    }

    fn machine(&self) -> Cow<str> {
        Cow::Borrowed("unknown")
    }

    fn osname(&self) -> Cow<str> {
        Cow::Borrowed("unknown")
    }
}

#[test]
fn test_unknown() {
    let platform_info = PlatformInfo::new().unwrap();

    assert_eq!(platform_info.sysname(), "unknown");
    assert_eq!(platform_info.nodename(), "unknown");
    assert_eq!(platform_info.release(), "unknown");
    assert_eq!(platform_info.version(), "unknown");
    assert_eq!(platform_info.machine(), "unknown");
    assert_eq!(platform_info.osname(), "unknown");
}
