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
use std::ffi::{CStr, OsStr, OsString};
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
    os_name: String,
    release: String,
    version: String,
}

/// `PlatformInfo` handles retrieving information for the current platform (Windows in this case).
pub struct PlatformInfo {
    sysinfo: SYSTEM_INFO,
    nodename: String,
    release: String,
    version: String,
    osname: String,
}

impl PlatformInfo {
    /// Creates a new instance of `PlatformInfo`.  Because of the way the information is retrieved,
    /// it is possible for this function to fail.
    pub fn new() -> io::Result<Self> {
        unsafe {
            let mut sysinfo = MaybeUninit::<SYSTEM_INFO>::uninit();
            GetNativeSystemInfo(sysinfo.as_mut_ptr());
            // SAFETY: `sysinfo` was initialized
            let sysinfo = sysinfo.assume_init();

            let version_info = Self::version_info()?;

            let nodename = Self::computer_name()?;

            Ok(Self {
                sysinfo,
                nodename,
                version: version_info.version,
                release: version_info.release,
                osname: format!("{} ({})", crate::HOST_OS_NAME, version_info.os_name),
            })
        }
    }

    fn computer_name() -> io::Result<String> {
        let mut size = 0;
        unsafe {
            // NOTE: shouldn't need to check the error because, on error, the required size will be
            //       stored in the size variable
            // XXX: verify that ComputerNameDnsHostname is the best option
            GetComputerNameExW(ComputerNameDnsHostname, ptr::null_mut(), &mut size);
        }

        let mut data: Vec<u16> = vec![0; size as usize];
        unsafe {
            if GetComputerNameExW(ComputerNameDnsHostname, data.as_mut_ptr(), &mut size) != 0 {
                Ok(String::from_utf16_lossy(&data))
            } else {
                // XXX: should this error or just return localhost?
                Err(io::Error::last_os_error())
            }
        }
    }

    // NOTE: the only reason any of this has to be done is Microsoft deprecated GetVersionEx() and
    //       it is now basically useless for us on Windows 8.1 and Windows 10
    // ref: <https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getversionexw> @@ <https://archive.is/bYAwT>
    // ref: <https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-osversioninfoexw> @@ <https://archive.is/n4hBb>
    unsafe fn version_info() -> io::Result<WinOSVersionInfo> {
        // busybox-v1.35.0 * `busybox uname -a` => "Windows_NT HOSTNAME 10.0 19044 x86_64 MS/Windows"
        let dll_wide: Vec<WCHAR> = OsStr::new("ntdll.dll")
            .encode_wide()
            .chain(iter::once(0))
            .collect();
        let module = GetModuleHandleW(dll_wide.as_ptr());
        if !module.is_null() {
            let funcname = CStr::from_bytes_with_nul_unchecked(b"RtlGetVersion\0");
            let func = GetProcAddress(module, funcname.as_ptr());
            if !func.is_null() {
                let func: extern "stdcall" fn(*mut RTL_OSVERSIONINFOEXW) -> NTSTATUS =
                    mem::transmute(func as *const ());

                let mut osinfo: RTL_OSVERSIONINFOEXW = mem::zeroed();
                osinfo.dwOSVersionInfoSize = mem::size_of::<RTL_OSVERSIONINFOEXW>() as _;

                if func(&mut osinfo) == STATUS_SUCCESS {
                    return Ok(WinOSVersionInfo {
                        os_name: Self::determine_os_name(
                            osinfo.dwMajorVersion,
                            osinfo.dwMinorVersion,
                            osinfo.dwBuildNumber,
                            osinfo.wProductType,
                            osinfo.wSuiteMask.into(),
                        ),
                        release: format!("{}.{}", osinfo.dwMajorVersion, osinfo.dwMinorVersion),
                        version: format!("{}", osinfo.dwBuildNumber),
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

        let pathbuf = Self::get_kernel32_path()?;

        let file_info = Self::get_file_version_info(pathbuf)?;
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
            os_name: Self::determine_os_name(major, minor, build, product_type, suite_mask),
            release: format!("{}.{}", major, minor),
            version: format!("{}", build),
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

            let mut pathbuf = PathBuf::from(OsString::from_wide(&buffer));
            pathbuf.push(file);

            Ok(pathbuf)
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
    fn sysname(&self) -> Cow<str> {
        // TODO: report if using MinGW instead of MSVC

        // XXX: if Rust ever works on Windows CE and winapi has the VER_PLATFORM_WIN32_CE
        //      constant, we should probably check for that
        Cow::from("Windows_NT") // prior art from `busybox` and MS (from std::env::var("OS"))
    }

    fn nodename(&self) -> Cow<str> {
        Cow::from(self.nodename.as_str())
    }

    // FIXME: definitely wrong
    fn release(&self) -> Cow<str> {
        Cow::from(self.release.as_str())
    }

    // FIXME: this is prob wrong
    fn version(&self) -> Cow<str> {
        Cow::from(self.version.as_str())
    }

    fn machine(&self) -> Cow<str> {
        let arch = unsafe { self.sysinfo.u.s().wProcessorArchitecture };

        let arch_str = match arch {
            PROCESSOR_ARCHITECTURE_AMD64 => "x86_64",
            PROCESSOR_ARCHITECTURE_INTEL => match self.sysinfo.wProcessorLevel {
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

        Cow::from(arch_str)
    }

    fn osname(&self) -> Cow<str> {
        Cow::from(self.osname.as_str())
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
    unsafe {
        let module = GetModuleHandleW(dll_wide.as_ptr());
        if !module.is_null() {
            let funcname = CStr::from_bytes_with_nul_unchecked(b"IsWow64Process\0");
            let func = GetProcAddress(module, funcname.as_ptr());
            if !func.is_null() {
                let func: extern "stdcall" fn(HANDLE, *mut BOOL) -> BOOL =
                    mem::transmute(func as *const ());

                // we don't bother checking for errors as we assume that means that we are not using
                // WoW64
                func(GetCurrentProcess(), &mut result);
            }
        }
    }

    result == TRUE
}

#[test]
fn test_sysname() {
    let info = PlatformInfo::new().unwrap();
    let expected: String = std::env::var("OS").unwrap_or_else(|_| String::from("Windows_NT"));
    println!("sysname = '{}'", info.sysname());
    assert_eq!(info.sysname(), expected);
}

#[test]
#[allow(non_snake_case)]
fn test_nodename_no_trailing_NUL() {
    let info = PlatformInfo::new().unwrap();
    let nodename = info.nodename();
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

    println!("machine = '{}'", info.machine());
    assert!(target.contains(&&*info.machine()));
}

#[test]
fn test_osname() {
    let info = PlatformInfo::new().unwrap();
    println!("osname = '{}'", info.osname());
    assert!(info.osname().starts_with(crate::HOST_OS_NAME));
}

#[test]
fn test_version_vs_version() {
    let version_via_dll = unsafe { PlatformInfo::version_info().unwrap() };
    let version_via_file = PlatformInfo::version_info_from_file().unwrap();

    println!("version (via dll) = '{:#?}'", version_via_dll);
    println!("version (via file) = '{:#?}'", version_via_file);

    assert_eq!(version_via_dll.os_name, version_via_file.os_name);
    assert_eq!(version_via_dll.release, version_via_file.release);
    // the "version" portions may differ, but should have only slight variation
    // * assume that "version" is convertible to u32 + "version" from file is always earlier/smaller and may differ only below the thousands digit
    // * ref: [NT Version Info (detailed)](https://en.wikipedia.org/wiki/Comparison_of_Microsoft_Windows_versions#Windows_NT) @@ <https://archive.is/FSkhj>
    assert!(
        (version_via_dll.version.parse::<u32>().unwrap()
            - version_via_file.version.parse::<u32>().unwrap())
            < 1000
    );
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
