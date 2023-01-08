// This file is part of the uutils coreutils package.
//
// (c) Jian Zeng <anonymousknight96 AT gmail.com>
// (c) Alex Lyon <arcterus@mail.com>
//
// For the full copyright and license information, please view the LICENSE file
// that was distributed with this source code.
//

extern crate libc;

use self::libc::{uname, utsname};
use super::Uname;
use std::borrow::Cow;
use std::ffi::CStr;
use std::io;
use std::mem::MaybeUninit;

macro_rules! cstr2cow {
    ($v:expr) => {
        unsafe { CStr::from_ptr($v.as_ref().as_ptr()).to_string_lossy() }
    };
}

/// `PlatformInfo` handles retrieving information for the current platform (a Unix-like operating
/// in this case).
pub struct PlatformInfo {
    inner: utsname,
}

impl PlatformInfo {
    /// Creates a new instance of `PlatformInfo`.  This function *should* never fail.
    pub fn new() -> io::Result<Self> {
        unsafe {
            let mut uts = MaybeUninit::<utsname>::uninit();
            if uname(uts.as_mut_ptr()) != -1 {
                // SAFETY: `uts` was initialized
                let uts = uts.assume_init();

                Ok(Self { inner: uts })
            } else {
                Err(io::Error::last_os_error())
            }
        }
    }
}

impl Uname for PlatformInfo {
    fn sysname(&self) -> Cow<str> {
        cstr2cow!(self.inner.sysname)
    }

    fn nodename(&self) -> Cow<str> {
        cstr2cow!(self.inner.nodename)
    }

    fn release(&self) -> Cow<str> {
        cstr2cow!(self.inner.release)
    }

    fn version(&self) -> Cow<str> {
        cstr2cow!(self.inner.version)
    }

    fn machine(&self) -> Cow<str> {
        cstr2cow!(self.inner.machine)
    }

    fn osname(&self) -> Cow<str> {
        Cow::Borrowed(crate::HOST_OS_NAME)
    }
}

#[test]
fn test_osname() {
    let info = PlatformInfo::new().unwrap();
    println!("osname = '{}'", info.osname());
    assert_eq!(PlatformInfo::new().unwrap().osname(), crate::HOST_OS_NAME);
}
