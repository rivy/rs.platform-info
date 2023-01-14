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
use std::ffi::{CStr, OsStr};
use std::io;
use std::mem::MaybeUninit;
use std::os::unix::ffi::OsStrExt;

// macro_rules! cstr2cow {
//     ($v:expr) => {
//         unsafe { CStr::from_ptr($v.as_ref().as_ptr()).to_string_lossy() }
//     };
// }

/// `PlatformInfo` handles retrieving information for the current platform (a Unix-like operating
/// in this case).
pub struct PlatformInfo {
    utsname: libc::utsname, /* aka "Unix Time-sharing System Name"; ref: <https://stackoverflow.com/questions/41669397/whats-the-meaning-of-utsname-in-linux> */
}

impl PlatformInfo {
    /// Creates a new instance of `PlatformInfo`.  This function *should* never fail.
    pub fn new() -> io::Result<Self> {
        unsafe {
            let mut uts = MaybeUninit::<utsname>::uninit();
            if uname(uts.as_mut_ptr()) != -1 {
                // SAFETY: `uname()` succeeded => `uts` was initialized
                Ok(Self {
                    utsname: uts.assume_init(),
                })
            } else {
                Err(io::Error::last_os_error())
            }
        }
    }
}

// ref: [Byte-to/from-String Conversions](https://nicholasbishop.github.io/rust-conversions) @@ <https://archive.is/AnDCY>

impl Uname for PlatformInfo {
    fn sysname(&self) -> Cow<OsStr> {
        unsafe {
            // std::borrow::Cow::Borrowed(&OsStr::from_bytes(
            //     CStr::from_ptr(self.utsname.sysname.as_ref().as_ptr()).to_bytes(),
            // ))
            Cow::from(OsStr::from_bytes(
                CStr::from_ptr(self.utsname.sysname.as_ref().as_ptr()).to_bytes(),
            ))
        }
    }

    fn nodename(&self) -> Cow<OsStr> {
        // cstr2cow!(self.utsname.nodename)
        unsafe {
            Cow::from(OsStr::from_bytes(
                CStr::from_ptr(self.utsname.nodename.as_ref().as_ptr()).to_bytes(),
            ))
        }
    }

    fn release(&self) -> Cow<OsStr> {
        // cstr2cow!(self.utsname.release)
        unsafe {
            Cow::from(OsStr::from_bytes(
                CStr::from_ptr(self.utsname.release.as_ref().as_ptr()).to_bytes(),
            ))
        }
    }

    fn version(&self) -> Cow<OsStr> {
        // cstr2cow!(self.utsname.version)
        unsafe {
            Cow::from(OsStr::from_bytes(
                CStr::from_ptr(self.utsname.version.as_ref().as_ptr()).to_bytes(),
            ))
        }
    }

    fn machine(&self) -> Cow<OsStr> {
        // cstr2cow!(self.utsname.machine)
        unsafe {
            Cow::from(OsStr::from_bytes(
                CStr::from_ptr(self.utsname.machine.as_ref().as_ptr()).to_bytes(),
            ))
        }
    }

    fn osname(&self) -> Cow<OsStr> {
        Cow::from(OsStr::new(crate::HOST_OS_NAME))
    }
}

#[test]
fn test_osname() {
    let info = PlatformInfo::new().unwrap();
    println!("osname = '{}'", info.osname().to_string_lossy());
    assert_eq!(
        PlatformInfo::new().unwrap().osname().to_string_lossy(),
        crate::HOST_OS_NAME
    );
}
