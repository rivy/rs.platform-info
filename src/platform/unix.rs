// This file is part of the uutils coreutils package.
//
// (c) Jian Zeng <anonymousknight96 AT gmail.com>
// (c) Alex Lyon <arcterus@mail.com>
//
// For the full copyright and license information, please view the LICENSE file
// that was distributed with this source code.

// spell-checker:ignore (API) nodename osname sysname
// spell-checker:ignore (libc) libc utsname
// spell-checker:ignore (names) Jian Zeng * anonymousknight96
// spell-checker:ignore (rust) uninit
// spell-checker:ignore (uutils) coreutils uutils
// spell-checker:ignore (VSCode) endregion

// refs:
// [Byte-to/from-String Conversions](https://nicholasbishop.github.io/rust-conversions) @@ <https://archive.is/AnDCY>

use std::borrow::Cow;
use std::convert::TryFrom;
use std::error::Error;
use std::ffi::{CStr, OsStr, OsString};
use std::io;
use std::mem::MaybeUninit;
use std::os::unix::ffi::OsStrExt;

use libc;

use crate::Uname;

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
    osname: OsString,
}

impl PlatformInfo {
    /// Creates a new instance of `PlatformInfo`.
    /// This function *should* never fail.
    pub fn new() -> Result<Self, Box<dyn Error>> {
        let utsname = utsname()?;
        Ok(Self {
            utsname,
            sysname: oss_from_cstr(&utsname.sysname),
            nodename: oss_from_cstr(&utsname.nodename),
            release: oss_from_cstr(&utsname.release),
            version: oss_from_cstr(&utsname.version),
            machine: oss_from_cstr(&utsname.machine),
            osname: OsString::from(crate::HOST_OS_NAME),
        })
    }
}

impl Uname for PlatformInfo {
    fn sysname(&self) -> Result<Cow<str>, &OsString> {
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
        match self.osname.to_str() {
            Some(str) => Ok(Cow::from(str)),
            None => Err(&self.osname),
        }
    }
}

//#region unsafe code

fn oss_from_cstr(slice: &[libc::c_char]) -> OsString {
    assert!(slice.len() < usize::try_from(isize::MAX).unwrap());
    assert!(slice.iter().position(|&c| c == 0 /* NUL */).unwrap() < slice.len());
    OsString::from(OsStr::from_bytes(
        unsafe { CStr::from_ptr(slice.as_ptr()) }.to_bytes(),
    ))
}

fn utsname() -> Result<libc::utsname, Box<dyn Error>> {
    let mut uts = MaybeUninit::<libc::utsname>::uninit();
    let result = unsafe { libc::uname(uts.as_mut_ptr()) };
    if result != -1 {
        // SAFETY: `libc::uname()` succeeded => `uts` was initialized
        Ok(unsafe { uts.assume_init() })
    } else {
        Err(Box::new(io::Error::last_os_error()))
    }
}

//#endregion (unsafe code)

//=== Tests

#[test]
fn test_osname() {
    let info = PlatformInfo::new().unwrap();
    let osname = match info.osname() {
        Ok(str) => {
            println!("osname = [{}]'{:?}'", str.len(), str);
            str
        }
        Err(os_s) => {
            let s = os_s.to_string_lossy();
            println!("osname = [{}]'{:?}' => '{}'", os_s.len(), os_s, s);
            Cow::from(String::from(s))
        }
    };
    assert!(osname.starts_with(crate::HOST_OS_NAME));
}
