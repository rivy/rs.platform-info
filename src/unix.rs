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
use std::ffi::{CStr, OsStr, OsString};
use std::io;
use std::mem::MaybeUninit;
use std::os::unix::ffi::OsStrExt;

// macro_rules! cstr2cow {
//     ($v:expr) => {
//         unsafe { CStr::from_ptr($v.as_ref().as_ptr()).to_string_lossy() }
//     };
// }

macro_rules! os_string_from_cstr {
    ($v:expr) => {
        OsString::from(OsStr::from_bytes(
            unsafe { CStr::from_ptr($v.as_ref().as_ptr().cast()) }.to_bytes(),
        ))
    };
}

/// `PlatformInfo` handles retrieving information for the current platform (a Unix-like operating
/// in this case).
pub struct PlatformInfo {
    pub utsname: libc::utsname, /* aka "Unix Time-sharing System Name"; ref: <https://stackoverflow.com/questions/41669397/whats-the-meaning-of-utsname-in-linux> */
    // * private-use fields
    sysname: OsString,
    nodename: OsString,
    release: OsString,
    version: OsString,
    machine: OsString,
}

impl PlatformInfo {
    /// Creates a new instance of `PlatformInfo`.  This function *should* never fail.
    pub fn new() -> io::Result<Self> {
        let mut uts = MaybeUninit::<utsname>::uninit();
        let result = unsafe { uname(uts.as_mut_ptr()) };
        if result != -1 {
            // SAFETY: `uname()` succeeded => `uts` was initialized
            let utsname = unsafe { uts.assume_init() };
            Ok(Self {
                utsname,
                sysname: os_string_from_cstr!(utsname.sysname),
                nodename: os_string_from_cstr!(utsname.nodename),
                release: os_string_from_cstr!(utsname.release),
                version: os_string_from_cstr!(utsname.version),
                machine: os_string_from_cstr!(utsname.machine),
            })
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

// ref: [Byte-to/from-String Conversions](https://nicholasbishop.github.io/rust-conversions) @@ <https://archive.is/AnDCY>

impl Uname for PlatformInfo {
    fn sysname(&self) -> Result<Cow<str>, &OsString> {
        // let p = self.utsname.sysname.as_ref().as_ptr();
        // let c_str = unsafe { CStr::from_ptr(p.cast()) };
        // match c_str.to_str() {
        //     Ok(str) => Ok(Cow::from(str)),
        //     Err(_) => Err(&OsStr::from_bytes(c_str.to_bytes()).to_os_string()),
        // }
        match self.sysname.to_str() {
            Some(str) => Ok(Cow::from(str)),
            None => Err(&self.sysname),
        }
    }

    fn nodename(&self) -> Result<Cow<str>, &OsString> {
        match self.nodename.to_str() {
            Some(str) => Ok(Cow::from(str)),
            None => Err(&self.nodename),
        }
    }

    fn release(&self) -> Result<Cow<str>, &OsString> {
        match self.release.to_str() {
            Some(str) => Ok(Cow::from(str)),
            None => Err(&self.release),
        }
    }

    fn version(&self) -> Result<Cow<str>, &OsString> {
        match self.version.to_str() {
            Some(str) => Ok(Cow::from(str)),
            None => Err(&self.version),
        }
    }

    fn machine(&self) -> Result<Cow<str>, &OsString> {
        match self.machine.to_str() {
            Some(str) => Ok(Cow::from(str)),
            None => Err(&self.machine),
        }
    }

    fn osname(&self) -> Result<Cow<str>, &OsString> {
        Ok(Cow::from(String::from(crate::HOST_OS_NAME)))
    }
}

#[test]
fn test_osname() {
    let info = PlatformInfo::new().unwrap();
    println!("osname = '{}'", info.osname().unwrap());
    assert_eq!(info.osname().unwrap(), crate::HOST_OS_NAME);
}
