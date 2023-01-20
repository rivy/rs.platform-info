// This file is part of the uutils coreutils package.
//
// (c) Alex Lyon <arcterus@mail.com>
//
// For the full copyright and license information, please view the LICENSE file
// that was distributed with this source code.

// Note: there no standardization of values for platform info (or `uname`), so mimic some current practices
// busybox-v1.35.0 * `busybox uname -a` => "Windows_NT HOSTNAME 10.0 19044 x86_64 MS/Windows"
// python-v3.8.3 => `uname_result(system='Windows', node='HOSTNAME', release='10', version='10.0.19044', machine='AMD64')`

// refs/research:
// [rust ~ std::ffi](https://doc.rust-lang.org/std/ffi)
// [rust ~ std::os::windows::ffi](https://doc.rust-lang.org/std/os/windows/ffi)
// [WTF-8/WTF-16](https://simonsapin.github.io/wtf-8/#ill-formed-utf-16) @@ <https://archive.is/MG7Aa>
// [Byte-to/from-String Conversions](https://nicholasbishop.github.io/rust-conversions) @@ <https://archive.is/AnDCY>
// [NT Version Info](https://en.wikipedia.org/wiki/Windows_NT) @@ <https://archive.is/GnnvF>
// [NT Version Info (summary)](https://simple.wikipedia.org/wiki/Windows_NT) @@ <https://archive.is/T2StZ>
// [NT Version Info (detailed)](https://en.wikipedia.org/wiki/Comparison_of_Microsoft_Windows_versions#Windows_NT) @@ <https://archive.is/FSkhj>

// spell-checker:ignore (abbrev) MSVC
// spell-checker:ignore (API) sysname osname nodename
// spell-checker:ignore (jargon) armv aarch
// spell-checker:ignore (rust) repr stdcall uninit
// spell-checker:ignore (uutils) coreutils uutils
// spell-checker:ignore (vars) mmbr
// spell-checker:ignore (VSCode) endregion
// spell-checker:ignore (WinAPI) ctypes CWSTR DWORDLONG dwStrucVersion FARPROC FIXEDFILEINFO HIWORD HMODULE libloaderapi LOWORD LPCSTR LPCVOID LPCWSTR lpdw LPDWORD lplp LPOSVERSIONINFOEXW LPSYSTEM lptstr LPVOID LPWSTR minwindef ntdef ntstatus OSVERSIONINFOEXW processthreadsapi PUINT SMALLBUSINESS SUITENAME sysinfo sysinfoapi sysinfoapi TCHAR TCHARs ULONGLONG WCHAR WCHARs winapi winbase winver WSTR wstring
// spell-checker:ignore (WinOS) ntdll

use std::borrow::Cow;
use std::convert::TryFrom;
use std::error::Error;
use std::ffi::CString;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fmt::{Debug, Formatter};
use std::io;
use std::mem::{self, MaybeUninit};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::Path;
use std::path::PathBuf;
use std::ptr;

use winapi::shared::minwindef::*;
use winapi::shared::ntdef::NTSTATUS;
use winapi::shared::ntstatus::*;
use winapi::um::libloaderapi::*;
use winapi::um::sysinfoapi;
use winapi::um::sysinfoapi::*;
use winapi::um::winbase::*;
use winapi::um::winnt::*;
use winapi::um::winver::*;

use crate::Uname;

type PathStr = Path;
type PathString = PathBuf;

#[allow(non_snake_case)]
#[allow(unused_variables)]
#[derive(Debug)]
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
pub struct WinOsVersionInfo {
    os_name: OsString,
    release: OsString,
    version: OsString,
}

#[derive(Debug)]
struct MmbrVersion {
    major: DWORD,
    minor: DWORD,
    build: DWORD,
    _release: DWORD,
}

fn to_c_string<S: AsRef<OsStr>>(os_str: S) -> CString {
    let nul = '\0';
    let s = os_str.as_ref().to_string_lossy();
    let leading_s = s.split(nul).next().unwrap_or(""); // string slice of leading non-NUL characters

    let maybe_c_string = CString::new(leading_s);
    assert!(maybe_c_string.is_ok()); //* failure here == algorithmic logic error => panic
    maybe_c_string.unwrap()
}

#[allow(clippy::upper_case_acronyms)]
type WSTR = Vec<WCHAR>;
#[allow(clippy::upper_case_acronyms)]
type CWSTR = Vec<WCHAR>;

fn to_c_wstring<S: AsRef<OsStr>>(os_str: S) -> CWSTR {
    let nul = 0;
    let mut wstring: WSTR = os_str.as_ref().encode_wide().collect();
    wstring.push(nul);

    let maybe_index_first_nul = wstring.iter().position(|&i| i == nul);
    assert!(maybe_index_first_nul.is_some()); //* failure here == algorithmic logic error => panic
    let index_first_nul = maybe_index_first_nul.unwrap();
    assert!(index_first_nul < wstring.len()); //* failure here == algorithmic logic error => panic
    CWSTR::from(&wstring[..(index_first_nul + 1)])
}

#[allow(non_snake_case)]
fn WinOsGetComputerName() -> Result<OsString, Box<dyn Error>> {
    // WINAPI_GetComputerNameExW
    // pub fn WinAPI_GetComputerNameExW(NameType: COMPUTER_NAME_FORMAT, lpBuffer: LPWSTR, nSize: LPDWORD) -> BOOL
    // ref: <https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getcomputernameexw> @@ <https://archive.is/Lgb7p>
    // * `nSize` ~ (in) specifies the size of the destination buffer (*lpBuffer) in TCHARs (aka WCHARs)
    // * `nSize` ~ (out) on *failure*, receives the buffer size required for the result, *including* the terminating null character
    // * `nSize` ~ (out) on *success*, receives the number of TCHARs (aka WCHARs) copied to the destination buffer, *not including* the terminating null character

    //## NameType ~ using "ComputerNameDnsHostname" vs "ComputerNamePhysicalDnsHostname"
    // * "ComputerNamePhysicalDnsHostname" *may* have a different (more specific) name when in a DNS cluster
    // * `uname -n` may show the more specific cluster name (see https://clusterlabs.org/pacemaker/doc/deprecated/en-US/Pacemaker/1.1/html/Clusters_from_Scratch/_short_node_names.html)
    // * under Linux/Wine, they are *exactly* the same ([from Wine patches msgs](https://www.winehq.org/pipermail/wine-patches/2002-November/004080.html))
    // * probably want the more specific in-cluster name, but, functionally, any difference will be very rare
    let name_type = ComputerNamePhysicalDnsHostname; // or ComputerNameDnsHostname

    let mut size: DWORD = 0;
    let mut data: Vec<WCHAR> = vec![0; usize::try_from(size)?];
    WinAPI_GetComputerNameExW(name_type, &mut data, &mut size);

    data = vec![0; usize::try_from(size)?];
    let result = WinAPI_GetComputerNameExW(name_type, &mut data, &mut size);
    if result != 0 {
        Ok(OsString::from_wide(&data[..usize::try_from(size)?]))
    } else {
        Err(Box::new(io::Error::last_os_error()))
    }
}

#[allow(non_snake_case)]
fn WinOsGetFileVersionInfo<P: AsRef<PathStr>>(
    file_path: P,
) -> Result<WinApiFileVersionInfo, Box<dyn Error>> {
    let file_version_size = WinAPI_GetFileVersionInfoSizeW(&file_path);
    if file_version_size == 0 {
        return Err(Box::new(io::Error::last_os_error()));
    }
    let mut data: Vec<BYTE> = vec![0; usize::try_from(file_version_size)?];
    let result =
        WinAPI_GetFileVersionInfoW(&file_path, file_version_size, data.as_mut_ptr() as *mut _);
    if result == FALSE {
        return Err(Box::new(io::Error::last_os_error()));
    }
    Ok(WinApiFileVersionInfo { data })
}

#[allow(non_snake_case)]
fn WinOsGetModuleProcAddress<P: AsRef<PathStr>, Q: AsRef<PathStr>>(
    module_name: P,
    proc_name: Q,
) -> FARPROC {
    let mut ptr: FARPROC = std::ptr::null_mut();
    let module = WinAPI_GetModuleHandle(module_name);
    if !module.is_null() {
        ptr = WinAPI_GetProcAddress(module, proc_name);
    }
    ptr
}

#[allow(non_snake_case)]
fn WinOsGetSystemDirectory() -> Result<PathString, Box<dyn Error>> {
    let required_buf_capacity: UINT = WinAPI_GetSystemDirectoryW(ptr::null_mut(), 0);
    let mut data: Vec<WCHAR> = vec![0; usize::try_from(required_buf_capacity)?];
    let result = WinAPI_GetSystemDirectoryW(data.as_mut_ptr(), required_buf_capacity);
    if result == 0 {
        return Err(Box::new(io::Error::last_os_error()));
    }
    let path = PathString::from(OsString::from_wide(&data[..usize::try_from(result)?]));
    Ok(path)
}

#[derive(Debug)]
pub struct WinApiFileVersionInfo {
    data: Vec<BYTE>,
}

pub struct WinApiSystemInfo(SYSTEM_INFO);

impl Debug for WinApiSystemInfo {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.debug_struct("WinApiSystemInfo")
            .field("wProcessorArchitecture", &self.wProcessorArchitecture())
            .field("dwPageSize", &self.0.dwPageSize)
            .field(
                "lpMinimumApplicationAddress",
                &self.0.lpMinimumApplicationAddress,
            )
            .field(
                "lpMaximumApplicationAddress",
                &self.0.lpMaximumApplicationAddress,
            )
            .field("dwActiveProcessorMask", &self.0.dwActiveProcessorMask)
            .field("dwNumberOfProcessors", &self.0.dwNumberOfProcessors)
            .field("dwProcessorType", &self.0.dwProcessorType)
            .field("dwAllocationGranularity", &self.0.dwAllocationGranularity)
            .field("wAllocationGranularity", &self.0.wProcessorLevel)
            .field("wAllocationRevision", &self.0.wProcessorRevision)
            .finish()
    }
}

/// `PlatformInfo` handles retrieving information for the current platform (Windows in this case).
#[derive(Debug)]
pub struct PlatformInfo {
    pub computer_name: OsString,
    pub system_info: WinApiSystemInfo,
    pub version_info: WinOsVersionInfo,
    // * private-use fields
    osname: OsString,
}

impl PlatformInfo {
    /// Creates a new instance of `PlatformInfo`.
    /// Because of the way the information is retrieved, it is possible for this function to fail.
    pub fn new() -> Result<Self, Box<dyn Error>> {
        let computer_name = WinOsGetComputerName()?;
        let system_info = WinApiSystemInfo(WinAPI_GetNativeSystemInfo());
        let version_info = Self::os_version_info()?;

        let mut osname = OsString::from(crate::HOST_OS_NAME);
        osname.extend([
            OsString::from(" ("),
            version_info.os_name.clone(),
            OsString::from(")"),
        ]);

        Ok(Self {
            computer_name,
            system_info,
            version_info,
            osname,
        })
    }

    // NOTE: the only reason any of this has to be done is Microsoft deprecated GetVersionEx() and
    //       it is now basically useless for us on Windows 8.1 and Windows 10
    // ref: <https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getversionexw> @@ <https://archive.is/bYAwT>
    // ref: <https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-osversioninfoexw> @@ <https://archive.is/n4hBb>
    fn os_version_info() -> Result<WinOsVersionInfo, Box<dyn Error>> {
        // busybox-v1.35.0 * `busybox uname -a` => "Windows_NT HOSTNAME 10.0 19044 x86_64 MS/Windows"
        match Self::os_version_info_from_dll() {
            Ok(os_info) => Ok(os_info),
            Err(_) => {
                // as a last resort, try to get the relevant info by loading the version info from a system file
                // Note: this file version may be just the current "base" version and not the actual most up-to-date version info
                // * eg: kernel32.dll (or ntdll.dll) version => "10.0.19041.2130" _vs_ `cmd /c ver` => "10.0.19044.2364"
                return Self::version_info_from_known_file();
            }
        }
    }

    fn os_version_info_from_dll() -> Result<WinOsVersionInfo, Box<dyn Error>> {
        match NTDLL_RtlGetVersion() {
            Ok(os_info) => Ok(WinOsVersionInfo {
                os_name: Self::determine_os_name(
                    os_info.dwMajorVersion,
                    os_info.dwMinorVersion,
                    os_info.dwBuildNumber,
                    os_info.wProductType,
                    os_info.wSuiteMask.into(),
                )
                .into(),
                release: format!("{}.{}", os_info.dwMajorVersion, os_info.dwMinorVersion).into(),
                version: format!("{}", os_info.dwBuildNumber).into(),
            }),
            Err(_status) => Err(format!("status: {}", _status).into()),
        }
    }

    fn os_version_info_from_file<P: AsRef<PathStr>>(
        path: P,
    ) -> Result<WinOsVersionInfo, Box<dyn Error>> {
        let file_info = Self::get_file_version_info(path)?;

        let v = Self::mmrb_from_version_info(file_info)?;

        let mut info = create_OSVERSIONINFOEXW()?;
        info.wSuiteMask = WORD::try_from(VER_SUITE_WH_SERVER)?;
        info.wProductType = VER_NT_WORKSTATION;

        let mask = WinAPI_VerSetConditionMask(0, VER_SUITENAME, VER_EQUAL);
        let suite_mask = if WinAPI_VerifyVersionInfoW(&mut info, VER_SUITENAME, mask) != 0 {
            VER_SUITE_WH_SERVER
        } else {
            0
        };

        let mask = WinAPI_VerSetConditionMask(0, VER_PRODUCT_TYPE, VER_EQUAL);
        let product_type = if WinAPI_VerifyVersionInfoW(&mut info, VER_PRODUCT_TYPE, mask) != 0 {
            VER_NT_WORKSTATION
        } else {
            0
        };

        Ok(WinOsVersionInfo {
            os_name: Self::determine_os_name(v.major, v.minor, v.build, product_type, suite_mask)
                .into(),
            release: format!("{}.{}", v.major, v.minor).into(),
            version: format!("{}", v.build).into(),
        })
    }

    fn version_info_from_known_file() -> Result<WinOsVersionInfo, Box<dyn Error>> {
        let path = Self::get_system_file_path("kernel32.dll")?;
        Self::os_version_info_from_file(path)
    }

    fn get_system_file_path<P: AsRef<PathStr>>(file_path: P) -> Result<PathString, Box<dyn Error>> {
        let system_path = WinOsGetSystemDirectory()?;
        let mut path = system_path;
        path.push(file_path.as_ref());
        Ok(path)
    }

    fn get_file_version_info<P: AsRef<PathStr>>(
        file_path: P,
    ) -> Result<WinApiFileVersionInfo, Box<dyn Error>> {
        WinOsGetFileVersionInfo(file_path)
    }

    fn mmrb_from_version_info(
        version_info: WinApiFileVersionInfo,
    ) -> Result<MmbrVersion, Box<dyn Error>> {
        let info = WinOsFileVersionInfoQuery_root(&version_info)?;
        Ok(MmbrVersion {
            major: DWORD::try_from(HIWORD(info.dwProductVersionMS))?,
            minor: DWORD::try_from(LOWORD(info.dwProductVersionMS))?,
            build: DWORD::try_from(HIWORD(info.dwProductVersionLS))?,
            _release: DWORD::try_from(LOWORD(info.dwProductVersionLS))?,
        })
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
        match self.computer_name.to_str() {
            Some(str) => Ok(Cow::from(str)),
            None => Err(&self.computer_name),
        }
    }

    fn release(&self) -> Result<Cow<str>, &OsString> {
        match self.version_info.release.to_str() {
            Some(str) => Ok(Cow::from(str)),
            None => Err(&self.version_info.release),
        }
    }

    fn version(&self) -> Result<Cow<str>, &OsString> {
        match self.version_info.version.to_str() {
            Some(str) => Ok(Cow::from(str)),
            None => Err(&self.version_info.version),
        }
    }

    fn machine(&self) -> Result<Cow<str>, &OsString> {
        let arch = self.system_info.wProcessorArchitecture();

        let arch_str = match arch {
            PROCESSOR_ARCHITECTURE_AMD64 => "x86_64",
            PROCESSOR_ARCHITECTURE_INTEL => match self.system_info.0.wProcessorLevel {
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

//#region unsafe code

#[allow(non_snake_case)]
fn create_OSVERSIONINFOEXW() -> Result<OSVERSIONINFOEXW, Box<dyn Error>> {
    // ref: <https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_osversioninfoexw> @@ <https://archive.is/CtlZS>
    let os_info_size = DWORD::try_from(mem::size_of::<OSVERSIONINFOEXW>())?;
    let mut os_info: RTL_OSVERSIONINFOEXW = unsafe { mem::zeroed() };
    os_info.dwOSVersionInfoSize = os_info_size;
    Ok(os_info)
}

// NOTE: WinAPI_... functions are essentially mechanical translations of the underlying WinOS API functions into safe functions
//   ... * except, LPCSTR and LPCWSTR arguments have been replaced with AsRef<PathStr> to avoid the need for fraught conversions of strings

#[allow(non_snake_case)]
fn WinAPI_GetComputerNameExW(
    name_type: COMPUTER_NAME_FORMAT,
    buffer: &mut Vec<WCHAR>, // buffer_ptr: LPWSTR,
    size: &mut DWORD,        // nSize: LPDWORD,
) -> BOOL {
    // GetComputerNameExW
    // pub unsafe fn GetComputerNameExW(NameType: COMPUTER_NAME_FORMAT, lpBuffer: LPWSTR, nSize: LPDWORD) -> BOOL
    // ref: <https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getcomputernameexw> @@ <https://archive.is/Lgb7p>
    let zero = DWORD::try_from(0).unwrap();
    let buffer_ptr = if *size > zero {
        buffer.as_mut_ptr()
    } else {
        ptr::null_mut()
    };
    assert!(!buffer_ptr.is_null() || (*size == zero));
    assert!((buffer.len() == 0) || (buffer.len() == usize::try_from(*size).unwrap()));
    unsafe { GetComputerNameExW(name_type, buffer_ptr, size) }
}

#[allow(dead_code)] // * used by test(s)
#[allow(non_snake_case)]
fn WinAPI_GetCurrentProcess() -> HANDLE {
    // GetCurrentProcess
    // pub unsafe fn GetCurrentProcess() -> HANDLE
    // ref: <https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocess> @@ <https://archive.is/AmB3f>
    unsafe { winapi::um::processthreadsapi::GetCurrentProcess() }
}

#[allow(non_snake_case)]
fn WinAPI_GetFileVersionInfoSizeW<P: AsRef<PathStr>>(
    file_path: P,
    // lpdwHandle: *mut DWORD, /* ignored */
) -> DWORD {
    // GetFileVersionInfoSizeW
    // pub unsafe fn GetFileVersionInfoSizeW(lptstrFilename: LPCWSTR, lpdwHandle: *mut DWORD) -> DWORD
    // ref: <https://learn.microsoft.com/en-us/windows/win32/api/winver/nf-winver-getfileversioninfosizew> @@ <https://archive.is/AdMHL>
    // * returns DWORD ~ on *failure*, 0
    // * returns DWORD ~ on *success*, size of the file version information, in *bytes*
    let file_path_cws = to_c_wstring(file_path.as_ref());
    unsafe { GetFileVersionInfoSizeW(file_path_cws.as_ptr(), ptr::null_mut()) }
}

#[allow(non_snake_case)]
fn WinAPI_GetFileVersionInfoW<P: AsRef<PathStr>>(
    file_path: P,
    // handle: DWORD, /* ignored */
    length: DWORD,
    data_ptr: *mut winapi::ctypes::c_void,
) -> BOOL {
    // GetFileVersionInfoW
    // pub unsafe fn GetFileVersionInfoW(lptstrFilename: LPCWSTR, dwHandle: DWORD, dwLen: DWORD, lpData: *mut c_void) -> BOOL
    // ref: <https://learn.microsoft.com/en-us/windows/win32/api/winver/nf-winver-getfileversioninfow> @@ <https://archive.is/4rx6D>
    // * handle/dwHandle == *ignored*
    // * length/dwLen == maximum size (in bytes) of buffer at data_ptr/lpData
    // * returns BOOL ~ `FALSE` for *fn failure*, o/w *fn success*
    let file_path_cws = to_c_wstring(file_path.as_ref());
    unsafe {
        GetFileVersionInfoW(
            file_path_cws.as_ptr(),
            0, /* ignored */
            length,
            data_ptr,
        )
    }
}

#[allow(non_snake_case)]
fn WinAPI_GetModuleHandle<P: AsRef<PathStr>>(module_name: P) -> HMODULE {
    // GetModuleHandleW
    // pub unsafe fn GetModuleHandleW(lpModuleName: LPCWSTR) -> HMODULE
    // ref: <https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlew> @@ <https://archive.is/HRusu>
    let module_name_cws = to_c_wstring(module_name.as_ref());
    unsafe { GetModuleHandleW(module_name_cws.as_ptr()) }
}

#[allow(non_snake_case)]
fn WinAPI_GetNativeSystemInfo() -> SYSTEM_INFO {
    // GetNativeSystemInfo
    // pub unsafe fn GetNativeSystemInfo(lpSystemInfo: LPSYSTEM_INFO)
    // ref: <https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getnativesysteminfo> @@ <https://archive.is/UV2S2>
    let mut sysinfo = MaybeUninit::<SYSTEM_INFO>::uninit();
    unsafe {
        GetNativeSystemInfo(sysinfo.as_mut_ptr());
        // SAFETY: `GetNativeSystemInfo()` always succeeds => `sysinfo` was initialized
        sysinfo.assume_init()
    }
}

#[allow(non_snake_case)]
fn WinAPI_GetProcAddress<P: AsRef<PathStr>>(module: HMODULE, proc_name: P) -> FARPROC {
    // GetProcAddress
    // pub unsafe fn GetProcAddress(hModule: HMODULE, lpProcName: LPCSTR) -> FARPROC
    // ref: <https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress> @@ <https://archive.is/ZPVMr>
    let proc_name_cws = to_c_string(proc_name.as_ref());
    unsafe { GetProcAddress(module, proc_name_cws.as_ptr()) }
}

#[allow(non_snake_case)]
fn WinAPI_GetSystemDirectoryW(buffer_ptr: LPWSTR, size: UINT) -> UINT {
    // GetSystemDirectoryW
    // pub unsafe fn GetSystemDirectoryW(lpBuffer: LPWSTR, uSize: UINT) -> UINT
    // ref: <https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress> @@ <https://archive.is/ZPVMr>
    // * `uSize` ~ (in) specifies the maximum size of the destination buffer (*lpBuffer) in TCHARs (aka WCHARs)
    // * returns UINT ~ on *fn failure*, 0
    // * returns UINT ~ on *fn success*, the number of TCHARs (aka WCHARs) copied to the destination buffer, *not including* the terminating null character
    unsafe { GetSystemDirectoryW(buffer_ptr, size) }
}

#[allow(non_snake_case)]
fn WinAPI_VerifyVersionInfoW(
    version_info_ptr: LPOSVERSIONINFOEXW,
    type_mask: DWORD,
    condition_mask: DWORDLONG,
) -> BOOL {
    // VerifyVersionInfoW
    // pub unsafe fn VerifyVersionInfoW(lpVersionInformation: LPOSVERSIONINFOEXW, dwTypeMask: DWORD, dwlConditionMask: DWORDLONG) -> BOOL
    // ref: <https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-verifyversioninfow> @@ <https://archive.is/1h5FF>
    unsafe { VerifyVersionInfoW(version_info_ptr, type_mask, condition_mask) }
}

#[allow(non_snake_case)]
fn WinAPI_VerQueryValueW<S: AsRef<str>>(
    version_info_ptr: LPCVOID,
    query: S,
    buffer_ptr: &mut LPVOID,
    length_ptr: PUINT,
) -> BOOL {
    // VerQueryValueW
    // pub unsafe fn VerQueryValueW(pBlock: LPCVOID, lpSubBlock: LPCWSTR, lplpBuffer: &mut LPVOID, puLen: PUINT) -> BOOL
    // ref: <https://learn.microsoft.com/en-us/windows/win32/api/winver/nf-winver-verqueryvaluew> @@ <https://archive.is/VqvGQ>
    unsafe {
        VerQueryValueW(
            version_info_ptr,
            to_c_wstring(query.as_ref()).as_ptr(),
            buffer_ptr,
            length_ptr,
        )
    }
}

#[allow(non_snake_case)]
fn WinAPI_VerSetConditionMask(
    condition_mask: ULONGLONG,
    type_mask: DWORD,
    condition: BYTE,
) -> ULONGLONG {
    // VerSetConditionMask
    // pub unsafe fn VerSetConditionMask(ConditionMask: ULONGLONG, TypeMask: DWORD, Condition: BYTE) -> ULONGLONG
    // ref: <https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-versetconditionmask> @@ <https://archive.is/hJtIB>
    unsafe { sysinfoapi::VerSetConditionMask(condition_mask, type_mask, condition) }
}

#[allow(non_snake_case)]
fn WinOsFileVersionInfoQuery_root(
    version_info: &WinApiFileVersionInfo,
) -> Result<&VS_FIXEDFILEINFO, Box<dyn Error>> {
    // NOTE: this function could be expanded to cover root, translation, and information queries by using an enum for a return value

    let version_info_data_block = &version_info.data;
    let mut block_size = 0;
    let mut block = ptr::null_mut();

    let fixed_file_info_block_size = UINT::try_from(mem::size_of::<VS_FIXEDFILEINFO>())?;

    let query = "\\";
    if WinAPI_VerQueryValueW(
        version_info_data_block.as_ptr() as *const _,
        query,
        &mut block,
        &mut block_size,
    ) == 0
        || (block_size != fixed_file_info_block_size)
    {
        return Err(Box::new(io::Error::last_os_error()));
    }

    // SAFETY: `block` was replaced with a non-null pointer
    // * lifetime of block/info is the same as input argument version_info
    Ok(unsafe { &*(block as *const VS_FIXEDFILEINFO) })
}

#[allow(dead_code)] // * used by test(s)
#[allow(non_snake_case)]
fn KERNEL32_IsWow64Process(process_handle: HANDLE) -> Result<bool, Box<dyn Error>> {
    // kernel32.dll/IsWow64Process
    // extern "stdcall" fn(HANDLE, *mut BOOL) -> BOOL
    // ref: <https://learn.microsoft.com/en-us/windows/win32/api/wow64apiset/nf-wow64apiset-iswow64process> @@ <https://archive.is/K00m6>
    let module = "kernel32.dll";
    let procedure = "IsWow64Process";
    let func = WinOsGetModuleProcAddress(module, procedure);
    if func.is_null() {
        return Err(Box::from(format!(
            "Unable to find DLL procedure '{}' within '{}'",
            procedure, module
        )));
    }

    let func: extern "stdcall" fn(HANDLE, *mut BOOL) -> BOOL =
        unsafe { mem::transmute(func as *const ()) };

    let mut is_wow64 = FALSE;

    let result = func(process_handle, &mut is_wow64);
    Ok((result != 0/* func() succeeded` */) && (is_wow64 != FALSE))
}

#[allow(non_snake_case)]
fn NTDLL_RtlGetVersion() -> Result<RTL_OSVERSIONINFOEXW, Box<dyn Error>> {
    // ntdll.dll/RtlGetVersion
    // extern "stdcall" fn(*mut RTL_OSVERSIONINFOEXW) -> NTSTATUS
    // ref: <https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlgetversion> @@ <https://archive.is/H1Ls2>
    let module = "ntdll.dll";
    let procedure = "RtlGetVersion";
    let func = WinOsGetModuleProcAddress(module, procedure);
    if func.is_null() {
        return Err(Box::from(format!(
            "Unable to find DLL procedure '{}' within '{}'",
            procedure, module
        )));
    }
    let func: extern "stdcall" fn(*mut RTL_OSVERSIONINFOEXW) -> NTSTATUS =
        unsafe { mem::transmute(func as *const ()) };

    let mut os_version_info = match create_OSVERSIONINFOEXW() {
        Ok(value) => value,
        Err(_) => return Err(Box::from("Unable to create OSVERSIONINFOEXW".to_string())),
    };

    let result = func(&mut os_version_info);
    if result == STATUS_SUCCESS {
        Ok(os_version_info)
    } else {
        Err(Box::from(format!(
            "RtlGetVersion() failed (result/status: {})",
            result
        )))
    }
}

impl WinApiSystemInfo {
    #[allow(non_snake_case)]
    pub fn wProcessorArchitecture(&self) -> WORD {
        unsafe { self.0.u.s().wProcessorArchitecture }
    }
}

//#endregion (unsafe code)

//=== Tests

#[test]
fn test_sysname() {
    let info = PlatformInfo::new().unwrap();
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
    let is_wow64 = KERNEL32_IsWow64Process(WinAPI_GetCurrentProcess()).unwrap_or_else(|_err| {
        println!("ERR: IsWow64Process(): {:#?}", _err);
        false
    });

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
    println!("target={:#?}", target);

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
    let version_via_dll = PlatformInfo::os_version_info_from_dll().unwrap();
    let version_via_file = PlatformInfo::version_info_from_known_file().unwrap();

    println!("version (via dll) = '{:#?}'", version_via_dll);
    println!("version (via known file) = '{:#?}'", version_via_file);

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
