// This file is part of the uutils coreutils package.
//
// (c) Ingvar Stepanyan <me@rreverser.com>
//
// For the full copyright and license information, please view the LICENSE file
// that was distributed with this source code.

// spell-checker:ignore (API) nodename osname sysname
// spell-checker:ignore (names) Ingvar Stepanyan * me@rreverser.com
// spell-checker:ignore (uutils) coreutils uutils

use super::Uname;
use std::borrow::Cow;

pub struct PlatformInfo(());

impl PlatformInfo {
    pub fn new() -> std::io::Result<Self> {
        Ok(Self(()))
    }
}

impl Uname for PlatformInfo {
    fn sysname(&self) -> Result<Cow<str>, &OsString> {
        Ok(Cow::from("unknown"))
    }

    fn nodename(&self) -> Result<Cow<str>, &OsString> {
        Ok(Cow::from("unknown"))
    }

    fn release(&self) -> Result<Cow<str>, &OsString> {
        Ok(Cow::from("unknown"))
    }

    fn version(&self) -> Result<Cow<str>, &OsString> {
        Ok(Cow::from("unknown"))
    }

    fn machine(&self) -> Result<Cow<str>, &OsString> {
        Ok(Cow::from("unknown"))
    }

    fn osname(&self) -> Result<Cow<str>, &OsString> {
        Ok(Cow::from("unknown"))
    }
}

#[test]
fn test_unknown() {
    let platform_info = PlatformInfo::new().unwrap();

    assert_eq!(platform_info.sysname().unwrap(), "unknown");
    assert_eq!(platform_info.nodename().unwrap(), "unknown");
    assert_eq!(platform_info.release().unwrap(), "unknown");
    assert_eq!(platform_info.version().unwrap(), "unknown");
    assert_eq!(platform_info.machine().unwrap(), "unknown");
    assert_eq!(platform_info.osname().unwrap(), "unknown");
}
