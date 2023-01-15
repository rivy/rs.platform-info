// This file is part of the uutils coreutils package.
//
// (c) Alex Lyon <arcterus@mail.com>
//
// For the full copyright and license information, please view the LICENSE file
// that was distributed with this source code.

// Note: there no standardization of values for platform info (or `uname`), so mimic some current practices
// busybox-v1.35.0 * `busybox uname -a` => "Windows_NT HOSTNAME 10.0 19044 x86_64 MS/Windows"
// python-v3.8.3 => `uname_result(system='Windows', node='HOSTNAME', release='10', version='10.0.19044', machine='AMD64')`

// refs:
// [NT Version Info](https://en.wikipedia.org/wiki/Windows_NT) @@ <https://archive.is/GnnvF>
// [NT Version Info (summary)](https://simple.wikipedia.org/wiki/Windows_NT) @@ <https://archive.is/T2StZ>
// [NT Version Info (detailed)](https://en.wikipedia.org/wiki/Comparison_of_Microsoft_Windows_versions#Windows_NT) @@ <https://archive.is/FSkhj>

// research ... [Research (rust OsString utf-8 wtf-8 utf-16 wft-16 ucs-2)](https://www.one-tab.com/page/kxXJHGhKRGuQ55UtJYNeAw) @@ <https://archive.is/CBp0i>

extern crate winapi;

use self::winapi::shared::minwindef::*;
use self::winapi::shared::ntdef::NTSTATUS;
use self::winapi::shared::ntstatus::*;
use self::winapi::um::libloaderapi::*;
use self::winapi::um::sysinfoapi::*;
use self::winapi::um::winbase::*;
use self::winapi::um::winnt::*;
use self::winapi::um::winver::*;
use super::Uname;
use std::borrow::Cow;
use std::convert::TryFrom;
use std::ffi::CStr;
use std::ffi::{OsStr, OsString};
use std::io;
use std::iter;
use std::mem::{self, MaybeUninit};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;
use std::ptr;

#[allow(unused_variables)]
#[allow(non_snake_case)]
#[repr(C)]
struct VS_FIXEDFILEINFO {
    dwSignature: DWORD,
    dwStrucVersion: DWORD,
    dwFileVersionMS: DWORD,
    dwFileVersionLS: DWORD,
    dwProductVersionMS: DWORD,
    dwProductVersionLS: DWORD,
    dwFileFlagsMask: DWORD,
    dwFileFlags: DWORD,
    dwFileOS: DWORD,
    dwFileType: DWORD,
    dwFileSubtype: DWORD,
    dwFileDateMS: DWORD,
    dwFileDateLS: DWORD,
}

#[derive(Debug)]
struct WinOSVersionInfo {
    os_name: OsString,
    release: OsString,
    version: OsString,
}

#[allow(non_snake_case)]
fn WinAPI_GetComputerNameExW() -> io::Result<OsString> {
    let mut size: DWORD = 0;
    unsafe {
        // NOTE: shouldn't need to check the error because, on error, the required size will be
        //       stored in the size variable
        // XXX: verify that ComputerNameDnsHostname is the best option
        // * ComputerNamePhysicalDnsHostname *may* have a different (more specific) name when in a DNS cluster
        // * for Wine, they are *exactly* the same ([from Wine patches msgs](https://www.winehq.org/pipermail/wine-patches/2002-November/004080.html))
        // * maybe add a test to make sure they are identical (additional code seems overly-cautious)
        // * `uname -n` may show the more specific cluster name (see https://clusterlabs.org/pacemaker/doc/deprecated/en-US/Pacemaker/1.1/html/Clusters_from_Scratch/_short_node_names.html)
        // * probably want the more specific in-cluster name, but, functionally, any difference will be very rare
        // ref: <https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getcomputernameexw> @@ <>
        // * `size` == (output) on *failure*, receives the buffer size required for the result, *including* the terminating null character*
        // * `size` == (output) on *success*, receives the number of TCHARs (aka WCHARs) copied to the destination buffer, *not including* the terminating null character
        GetComputerNameExW(ComputerNameDnsHostname, ptr::null_mut(), &mut size);
        // GetComputerNameExW(ComputerNamePhysicalDnsHostname, ptr::null_mut(), &mut size);
    }

    let mut data: Vec<WCHAR> = vec![0; usize::try_from(size).unwrap()];
    let result = unsafe {
        GetComputerNameExW(
            ComputerNameDnsHostname,
            // ComputerNamePhysicalDnsHostname,
            data.as_mut_ptr(),
            &mut size,
        )
    };
    if result != 0 {
        // ref: https://doc.rust-lang.org/std/os/windows/ffi/index.html
        // ref: [WTF-8/WTF-16](https://simonsapin.github.io/wtf-8/#ill-formed-utf-16)
        // * ??? to use within `rust` String, the data must be converted to well-formed UTF (maybe we could use an OSString)
        // Ok(String::from_utf16_lossy(&data))
        // * note: read ... https://internals.rust-lang.org/t/prerfc-trait-converting-functions-for-osstring/11634/14
        // * read: ... https://users.rust-lang.org/t/tidy-pattern-to-work-with-lpstr-mutable-char-array/2976
        // println!("{:#?}", data);
        // let s = OsString::from_wide(&data);
        // let s = OsString::from_wide(&data[..usize::try_from(size).unwrap_or(usize::MAX)]);
        // let s = OsString::from_wide(&data[..usize::try_from(size).unwrap()]);
        // println!("s[{}]='{}'", s.len(), s.to_string_lossy());

        Ok(OsString::from_wide(
            // &data[..usize::try_from(size).unwrap_or(usize::MAX)],
            &data[..usize::try_from(size).unwrap()],
        ))
    } else {
        // XXX: should this error or just return localhost?
        Err(io::Error::last_os_error())
    }
}

#[allow(non_snake_case)]
fn WinAPI_GetNativeSystemInfo() -> SYSTEM_INFO {
    let mut sysinfo = MaybeUninit::<SYSTEM_INFO>::uninit();
    unsafe {
        GetNativeSystemInfo(sysinfo.as_mut_ptr());
        // SAFETY: `GetNativeSystemInfo()` always succeeds => `sysinfo` was initialized
        sysinfo.assume_init()
    }
}

/// `PlatformInfo` handles retrieving information for the current platform (Windows in this case).
pub struct PlatformInfo {
    pub system_info: SYSTEM_INFO,
    // * private-use fields
    nodename: OsString,
    release: OsString,
    version: OsString,
    osname: OsString,
}

impl PlatformInfo {
    /// Creates a new instance of `PlatformInfo`.  Because of the way the information is retrieved,
    /// it is possible for this function to fail.
    pub fn new() -> io::Result<Self> {
        let sysinfo = WinAPI_GetNativeSystemInfo();
        // unsafe {
        // let mut sysinfo = MaybeUninit::<SYSTEM_INFO>::uninit();
        // GetNativeSystemInfo(sysinfo.as_mut_ptr());
        // // SAFETY: `GetNativeSystemInfo()` always succeeds => `sysinfo` was initialized
        // let sysinfo = sysinfo.assume_init();

        let nodename = Self::computer_name()?;

        let version_info = Self::version_info()?;

        let mut osname = OsString::from(crate::HOST_OS_NAME);
        osname.extend([
            OsString::from(" ("),
            version_info.os_name,
            OsString::from(")"),
        ]);

        Ok(Self {
            system_info: sysinfo,
            nodename,
            release: version_info.release,
            version: version_info.version,
            osname,
        })
        // }
    }

    fn computer_name() -> io::Result<OsString> {
        WinAPI_GetComputerNameExW()
    }

    // NOTE: the only reason any of this has to be done is Microsoft deprecated GetVersionEx() and
    //       it is now basically useless for us on Windows 8.1 and Windows 10
    // ref: <https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getversionexw> @@ <https://archive.is/bYAwT>
    // ref: <https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-osversioninfoexw> @@ <https://archive.is/n4hBb>
    fn version_info() -> io::Result<WinOSVersionInfo> {
        // busybox-v1.35.0 * `busybox uname -a` => "Windows_NT HOSTNAME 10.0 19044 x86_64 MS/Windows"
        let dll_wide: Vec<WCHAR> = OsStr::new("ntdll.dll")
            .encode_wide()
            .chain(iter::once(0))
            .collect();
        let module = unsafe { GetModuleHandleW(dll_wide.as_ptr()) };
        if !module.is_null() {
            let func_name = unsafe { CStr::from_bytes_with_nul_unchecked(b"RtlGetVersion\0") };
            // let func_name = CString::new("RtlGetVersion")?;
            let func = unsafe { GetProcAddress(module, func_name.as_ptr()) };
            if !func.is_null() {
                let func: extern "stdcall" fn(*mut RTL_OSVERSIONINFOEXW) -> NTSTATUS =
                    unsafe { mem::transmute(func as *const ()) };

                let mut os_info: RTL_OSVERSIONINFOEXW = unsafe { mem::zeroed() };
                os_info.dwOSVersionInfoSize =
                    u32::try_from(mem::size_of::<RTL_OSVERSIONINFOEXW>()).unwrap();

                if func(&mut os_info) == STATUS_SUCCESS {
                    return Ok(WinOSVersionInfo {
                        os_name: Self::determine_os_name(
                            os_info.dwMajorVersion,
                            os_info.dwMinorVersion,
                            os_info.dwBuildNumber,
                            os_info.wProductType,
                            os_info.wSuiteMask.into(),
                        )
                        .into(),
                        release: format!("{}.{}", os_info.dwMajorVersion, os_info.dwMinorVersion)
                            .into(),
                        version: format!("{}", os_info.dwBuildNumber).into(),
                    });
                }
            }
        }

        // as a last resort, try to get the relevant info by loading the version info from a system
        // file (specifically Kernel32.dll)
        // Note: this file version may be just the current "base" version and not the actual most up-to-date version info
        // * eg: kernel32.dll (or ntdll.dll) version => "10.0.19041.2130" _vs_ `cmd /c ver` => "10.0.19044.2364"
        Self::version_info_from_file()
    }

    fn version_info_from_file() -> io::Result<WinOSVersionInfo> {
        use self::winapi::um::sysinfoapi;

        let path = Self::get_kernel32_path()?;

        let file_info = Self::get_file_version_info(path)?;
        let (major, minor, build, _revision) = Self::query_version_info(file_info)?;

        // SAFETY: this is valid
        let mut info = unsafe { mem::zeroed::<OSVERSIONINFOEXW>() };
        info.wSuiteMask = VER_SUITE_WH_SERVER as WORD;
        info.wProductType = VER_NT_WORKSTATION;

        let mask = unsafe { sysinfoapi::VerSetConditionMask(0, VER_SUITENAME, VER_EQUAL) };
        let suite_mask = if unsafe { VerifyVersionInfoW(&mut info, VER_SUITENAME, mask) } != 0 {
            VER_SUITE_WH_SERVER
        } else {
            0
        };

        let mask = unsafe { sysinfoapi::VerSetConditionMask(0, VER_PRODUCT_TYPE, VER_EQUAL) };
        let product_type = if unsafe { VerifyVersionInfoW(&mut info, VER_PRODUCT_TYPE, mask) } != 0
        {
            VER_NT_WORKSTATION
        } else {
            0
        };

        Ok(WinOSVersionInfo {
            os_name: Self::determine_os_name(major, minor, build, product_type, suite_mask).into(),
            release: format!("{}.{}", major, minor).into(),
            version: format!("{}", build).into(),
        })
    }

    fn get_kernel32_path() -> io::Result<PathBuf> {
        let file = OsStr::new("Kernel32.dll");
        // the "- 1" is to account for the path separator
        let buf_capacity = MAX_PATH - file.len() - 1;

        let mut buffer = Vec::with_capacity(buf_capacity);
        let buf_size = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buf_capacity as UINT) };

        if buf_size >= buf_capacity as UINT || buf_size == 0 {
            Err(io::Error::last_os_error())
        } else {
            unsafe {
                buffer.set_len(buf_size as usize);
            }

            let mut path = PathBuf::from(OsString::from_wide(&buffer));
            path.push(file);

            Ok(path)
        }
    }

    fn get_file_version_info(path: PathBuf) -> io::Result<Vec<u8>> {
        let path_wide: Vec<_> = path
            .as_os_str()
            .encode_wide()
            .chain(iter::once(0))
            .collect();
        let fver_size = unsafe { GetFileVersionInfoSizeW(path_wide.as_ptr(), ptr::null_mut()) };

        if fver_size == 0 {
            return Err(io::Error::last_os_error());
        }

        let mut buffer = Vec::with_capacity(fver_size as usize);
        if unsafe {
            GetFileVersionInfoW(
                path_wide.as_ptr(),
                0,
                fver_size,
                buffer.as_mut_ptr() as *mut _,
            )
        } == 0
        {
            Err(io::Error::last_os_error())
        } else {
            unsafe {
                buffer.set_len(fver_size as usize);
            }
            Ok(buffer)
        }
    }

    fn query_version_info(buffer: Vec<u8>) -> io::Result<(DWORD, DWORD, DWORD, DWORD)> {
        let mut block_size = 0;
        let mut block = ptr::null_mut();

        let sub_block: Vec<_> = OsStr::new("\\")
            .encode_wide()
            .chain(iter::once(0))
            .collect();
        if unsafe {
            VerQueryValueW(
                buffer.as_ptr() as *const _,
                sub_block.as_ptr(),
                &mut block,
                &mut block_size,
            ) == 0
                && block_size < mem::size_of::<VS_FIXEDFILEINFO>() as UINT
        } {
            return Err(io::Error::last_os_error());
        }

        // SAFETY: `block` was replaced with a non-null pointer
        let info = unsafe { &*(block as *const VS_FIXEDFILEINFO) };

        Ok((
            HIWORD(info.dwProductVersionMS) as _,
            LOWORD(info.dwProductVersionMS) as _,
            HIWORD(info.dwProductVersionLS) as _,
            LOWORD(info.dwProductVersionLS) as _,
        ))
    }

    fn determine_os_name(
        major: DWORD,
        minor: DWORD,
        build: DWORD,
        product_type: BYTE,
        suite_mask: DWORD,
    ) -> String {
        // [NT Version Info (detailed)](https://en.wikipedia.org/wiki/Comparison_of_Microsoft_Windows_versions#Windows_NT) @@ <https://archive.is/FSkhj>
        let default_name = if product_type == VER_NT_WORKSTATION {
            format!("{} {}.{}", "Windows", major, minor)
        } else {
            format!("{} {}.{}", "Windows Server", major, minor)
        };

        let name = match major {
            5 => match minor {
                0 => "Windows 2000",
                1 => "Windows XP",
                2 if product_type == VER_NT_WORKSTATION => "Windows XP Professional x64 Edition",
                2 if suite_mask == VER_SUITE_WH_SERVER => "Windows Home Server",
                2 => "Windows Server 2003",
                _ => &default_name,
            },
            6 => match minor {
                0 if product_type == VER_NT_WORKSTATION => "Windows Vista",
                0 => "Windows Server 2008",
                1 if product_type != VER_NT_WORKSTATION => "Windows Server 2008 R2",
                1 => "Windows 7",
                2 if product_type != VER_NT_WORKSTATION => "Windows Server 2012",
                2 => "Windows 8",
                3 if product_type != VER_NT_WORKSTATION => "Windows Server 2012 R2",
                3 => "Windows 8.1",
                _ => &default_name,
            },
            10 => match minor {
                0 if product_type == VER_NT_WORKSTATION && (build >= 22000) => "Windows 11",
                0 if product_type != VER_NT_WORKSTATION && (14000..17000).contains(&build) => {
                    "Windows Server 2016"
                }
                0 if product_type != VER_NT_WORKSTATION && (17000..19000).contains(&build) => {
                    "Windows Server 2019"
                }
                0 if product_type != VER_NT_WORKSTATION && (build >= 20000) => {
                    "Windows Server 2022"
                }
                _ => "Windows 10",
            },
            _ => &default_name,
        };

        name.to_string()
    }
}

impl Uname for PlatformInfo {
    fn sysname(&self) -> Result<Cow<str>, &OsString> {
        // TODO: report if using MinGW instead of MSVC

        // XXX: if Rust ever works on Windows CE and winapi has the VER_PLATFORM_WIN32_CE
        //      constant, we should probably check for that
        Ok(Cow::from("Windows_NT")) // prior art from `busybox` and MS (from std::env::var("OS"))
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
        let arch = unsafe { self.system_info.u.s().wProcessorArchitecture };

        let arch_str = match arch {
            PROCESSOR_ARCHITECTURE_AMD64 => "x86_64",
            PROCESSOR_ARCHITECTURE_INTEL => match self.system_info.wProcessorLevel {
                4 => "i486",
                5 => "i586",
                6 => "i686",
                _ => "i386",
            },
            PROCESSOR_ARCHITECTURE_IA64 => "ia64",
            // FIXME: not sure if this is wrong because I think uname usually returns stuff like
            //        armv7l on Linux, but can't find a way to figure that out on Windows
            PROCESSOR_ARCHITECTURE_ARM => "arm",
            // XXX: I believe this is correct for GNU compat, but differs from LLVM?  Like the ARM
            //      branch above, I'm not really sure about this one either
            PROCESSOR_ARCHITECTURE_ARM64 => "aarch64",
            PROCESSOR_ARCHITECTURE_MIPS => "mips",
            PROCESSOR_ARCHITECTURE_PPC => "powerpc",
            PROCESSOR_ARCHITECTURE_ALPHA | PROCESSOR_ARCHITECTURE_ALPHA64 => "alpha",
            // FIXME: I don't know anything about this architecture, so this may be incorrect
            PROCESSOR_ARCHITECTURE_SHX => "sh",
            _ => "unknown",
        };

        Ok(Cow::from(arch_str))
    }

    fn osname(&self) -> Result<Cow<str>, &OsString> {
        match self.osname.to_str() {
            Some(str) => Ok(Cow::from(str)),
            None => Err(&self.osname),
        }
    }
}

#[cfg(test)]
fn is_wow64() -> bool {
    use self::winapi::um::processthreadsapi::*;

    let mut result = FALSE;

    let dll_wide: Vec<WCHAR> = OsStr::new("Kernel32.dll")
        .encode_wide()
        .chain(iter::once(0))
        .collect();
    let module = unsafe { GetModuleHandleW(dll_wide.as_ptr()) };
    if !module.is_null() {
        let func_name = unsafe { CStr::from_bytes_with_nul_unchecked(b"IsWow64Process\0") };
        // let func_name = CString::from("IsWow64Process");
        let func = unsafe { GetProcAddress(module, func_name.as_ptr()) };
        if !func.is_null() {
            let func: extern "stdcall" fn(HANDLE, *mut BOOL) -> BOOL =
                unsafe { mem::transmute(func as *const ()) };

            // we don't bother checking for errors as we assume that means that we are not using
            // WoW64
            func(unsafe { GetCurrentProcess() }, &mut result);
        }
    }

    result == TRUE
}

// fn into_lossy(AsRef<OsStr> )

#[test]
fn test_sysname() {
    let info = PlatformInfo::new().unwrap();
    // let result = info.sysname();

    // Result<Cow<str>, Cow<OsStr>>
    // let sysname = info
    //     .sysname()
    //     .unwrap_or_else(|os_str| String::from(os_str.to_string_lossy()).into());
    // let sysname = match info.sysname() {
    //     Ok(str) => {
    //         println!("sysname = [{}]'{:?}'", str.len(), str);
    //         str
    //     }
    //     Err(os_str) => {
    //         let s = os_str.to_string_lossy();
    //         println!("sysname = [{}]'{:?}' => '{}'", os_str.len(), os_str, s);
    //         Cow::from(String::from(s))
    //     }
    // };

    // Result<Cow<str>, &OsString>
    // let sysname = (info.sysname()).unwrap_or_else(|os_string| os_string.to_string_lossy());
    let sysname = match info.sysname() {
        Ok(str) => {
            println!("sysname = [{}]'{:?}'", str.len(), str);
            str
        }
        Err(os_s) => {
            let s = os_s.to_string_lossy();
            println!("sysname = [{}]'{:?}' => '{}'", os_s.len(), os_s, s);
            Cow::from(String::from(s))
        }
    };

    // .unwrap_or_else(|os_str| os_str.to_string_lossy());
    // // let sysname = sysname_os.to_string_lossy();
    // let sysname = sysname_os.clone();
    // println!("sysname = [{}]'{:?}'", sysname.len(), sysname);
    // let expected: OsString = std::env::var_os("OS").unwrap_or_else(|| OsString::from("Windows_NT"));
    let expected = std::env::var("OS").unwrap_or_else(|_| String::from("Windows_NT"));
    assert_eq!(sysname, expected);
}

#[test]
#[allow(non_snake_case)]
fn test_nodename_no_trailing_NUL() {
    let info = PlatformInfo::new().unwrap();
    let nodename = match info.nodename() {
        Ok(str) => {
            println!("nodename = [{}]'{:?}'", str.len(), str);
            str
        }
        Err(os_s) => {
            let s = os_s.to_string_lossy();
            println!("nodename = [{}]'{:?}' => '{}'", os_s.len(), os_s, s);
            Cow::from(String::from(s))
        }
    };
    let trimmed = nodename.trim().trim_end_matches(|c| c == '\0');
    assert_eq!(nodename, trimmed);
}

#[test]
fn test_machine() {
    let is_wow64 = is_wow64();
    let target = if cfg!(target_arch = "x86_64") || (cfg!(target_arch = "x86") && is_wow64) {
        vec!["x86_64"]
    } else if cfg!(target_arch = "x86") {
        vec!["i386", "i486", "i586", "i686"]
    } else if cfg!(target_arch = "arm") {
        vec!["arm"]
    } else if cfg!(target_arch = "aarch64") {
        // NOTE: keeping both of these until the correct behavior is sorted out
        vec!["arm64", "aarch64"]
    } else if cfg!(target_arch = "powerpc") {
        vec!["powerpc"]
    } else if cfg!(target_arch = "mips") {
        vec!["mips"]
    } else {
        // NOTE: the other architecture are currently not valid targets for Rust (in fact, I am
        //       almost certain some of these are not even valid targets for the Windows build)
        vec!["unknown"]
    };

    let info = PlatformInfo::new().unwrap();
    let machine = match info.machine() {
        Ok(str) => {
            println!("machine = [{}]'{:?}'", str.len(), str);
            str
        }
        Err(os_s) => {
            let s = os_s.to_string_lossy();
            println!("machine = [{}]'{:?}' => '{}'", os_s.len(), os_s, s);
            Cow::from(String::from(s))
        }
    };

    assert!(target.contains(&&machine[..]));
}

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

#[test]
fn test_version_vs_version() {
    let version_via_dll = PlatformInfo::version_info().unwrap();
    let version_via_file = PlatformInfo::version_info_from_file().unwrap();

    println!("version (via dll) = '{:#?}'", version_via_dll);
    println!("version (via file) = '{:#?}'", version_via_file);

    assert_eq!(version_via_dll.os_name, version_via_file.os_name);
    assert_eq!(version_via_dll.release, version_via_file.release);
    // the "version" portions may differ, but should have only slight variation
    // * assume that "version" is convertible to u32 + "version" from file is always earlier/smaller and may differ only below the thousands digit
    // * ref: [NT Version Info (detailed)](https://en.wikipedia.org/wiki/Comparison_of_Microsoft_Windows_versions#Windows_NT) @@ <https://archive.is/FSkhj>
    let version_via_dll_n = version_via_dll
        .version
        .to_string_lossy()
        .parse::<u32>()
        .unwrap();
    let version_via_file_n = version_via_file
        .version
        .to_string_lossy()
        .parse::<u32>()
        .unwrap();
    assert!(version_via_dll_n.checked_sub(version_via_file_n) < Some(1000));
}

#[test]
fn test_known_os_names() {
    // ref: [NT Version Info (detailed)](https://en.wikipedia.org/wiki/Comparison_of_Microsoft_Windows_versions#Windows_NT) @@ <https://archive.is/FSkhj>
    assert_eq!(
        PlatformInfo::determine_os_name(3, 1, 528, VER_NT_WORKSTATION, VER_SUITE_PERSONAL),
        "Windows 3.1"
    );
    assert_eq!(
        PlatformInfo::determine_os_name(3, 5, 807, VER_NT_WORKSTATION, VER_SUITE_PERSONAL),
        "Windows 3.5"
    );
    assert_eq!(
        PlatformInfo::determine_os_name(3, 51, 1057, VER_NT_WORKSTATION, VER_SUITE_PERSONAL),
        "Windows 3.51"
    );
    assert_eq!(
        PlatformInfo::determine_os_name(4, 0, 1381, VER_NT_WORKSTATION, VER_SUITE_PERSONAL),
        "Windows 4.0"
    );
    assert_eq!(
        PlatformInfo::determine_os_name(5, 0, 2195, VER_NT_WORKSTATION, VER_SUITE_PERSONAL),
        "Windows 2000"
    );
    assert_eq!(
        PlatformInfo::determine_os_name(5, 1, 2600, VER_NT_WORKSTATION, VER_SUITE_PERSONAL),
        "Windows XP"
    );
    assert_eq!(
        PlatformInfo::determine_os_name(5, 2, 3790, VER_NT_WORKSTATION, VER_SUITE_PERSONAL),
        "Windows XP Professional x64 Edition"
    );
    assert_eq!(
        PlatformInfo::determine_os_name(5, 2, 3790, VER_NT_SERVER, VER_SUITE_WH_SERVER),
        "Windows Home Server"
    );
    assert_eq!(
        PlatformInfo::determine_os_name(5, 2, 3790, VER_NT_SERVER, VER_SUITE_SMALLBUSINESS),
        "Windows Server 2003"
    );
    assert_eq!(
        PlatformInfo::determine_os_name(5, 2, 3790, VER_NT_SERVER, VER_SUITE_SMALLBUSINESS),
        "Windows Server 2003"
    );
    assert_eq!(
        PlatformInfo::determine_os_name(6, 0, 6000, VER_NT_WORKSTATION, VER_SUITE_PERSONAL),
        "Windows Vista"
    );
    assert_eq!(
        PlatformInfo::determine_os_name(6, 0, 6001, VER_NT_SERVER, VER_SUITE_SMALLBUSINESS),
        "Windows Server 2008"
    );
    assert_eq!(
        PlatformInfo::determine_os_name(6, 1, 7600, VER_NT_WORKSTATION, VER_SUITE_PERSONAL),
        "Windows 7"
    );
    assert_eq!(
        PlatformInfo::determine_os_name(6, 1, 7600, VER_NT_SERVER, VER_SUITE_SMALLBUSINESS),
        "Windows Server 2008 R2"
    );
    assert_eq!(
        PlatformInfo::determine_os_name(6, 2, 9200, VER_NT_SERVER, VER_SUITE_SMALLBUSINESS),
        "Windows Server 2012"
    );
    assert_eq!(
        PlatformInfo::determine_os_name(6, 2, 9200, VER_NT_WORKSTATION, VER_SUITE_PERSONAL),
        "Windows 8"
    );
    assert_eq!(
        PlatformInfo::determine_os_name(6, 3, 9600, VER_NT_WORKSTATION, VER_SUITE_PERSONAL),
        "Windows 8.1"
    );
    assert_eq!(
        PlatformInfo::determine_os_name(6, 3, 9600, VER_NT_SERVER, VER_SUITE_SMALLBUSINESS),
        "Windows Server 2012 R2"
    );
    assert_eq!(
        PlatformInfo::determine_os_name(10, 0, 10240, VER_NT_WORKSTATION, VER_SUITE_PERSONAL),
        "Windows 10"
    );
    assert_eq!(
        PlatformInfo::determine_os_name(10, 0, 17134, VER_NT_WORKSTATION, VER_SUITE_PERSONAL),
        "Windows 10"
    );
    assert_eq!(
        PlatformInfo::determine_os_name(10, 0, 19141, VER_NT_WORKSTATION, VER_SUITE_PERSONAL),
        "Windows 10"
    );
    assert_eq!(
        PlatformInfo::determine_os_name(10, 0, 19145, VER_NT_WORKSTATION, VER_SUITE_PERSONAL),
        "Windows 10"
    );
    assert_eq!(
        PlatformInfo::determine_os_name(10, 0, 14393, VER_NT_SERVER, VER_SUITE_SMALLBUSINESS),
        "Windows Server 2016"
    );
    assert_eq!(
        PlatformInfo::determine_os_name(10, 0, 17763, VER_NT_SERVER, VER_SUITE_SMALLBUSINESS),
        "Windows Server 2019"
    );
    assert_eq!(
        PlatformInfo::determine_os_name(10, 0, 20348, VER_NT_SERVER, VER_SUITE_SMALLBUSINESS),
        "Windows Server 2022"
    );
    assert_eq!(
        PlatformInfo::determine_os_name(10, 0, 22000, VER_NT_WORKSTATION, VER_SUITE_PERSONAL),
        "Windows 11"
    );
    assert_eq!(
        PlatformInfo::determine_os_name(10, 0, 22621, VER_NT_WORKSTATION, VER_SUITE_PERSONAL),
        "Windows 11"
    );
}
