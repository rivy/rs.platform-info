// examples/t-win.rs
// * use `cargo run --features windows --example t-win` to execute this example

// spell-checker:ignore (abbrev) MSVC
// spell-checker:ignore (API) sysname osname nodename
// spell-checker:ignore (jargon) armv aarch
// spell-checker:ignore (rust) repr stdcall uninit
// spell-checker:ignore (uutils) coreutils uutils
// spell-checker:ignore (WinAPI) dwStrucVersion FARPROC FIXEDFILEINFO HIWORD HMODULE libloaderapi LOWORD LPCSTR LPCWSTR LPDWORD LPSYSTEM LPVOID LPWSTR minwindef ntdef ntstatus OSVERSIONINFOEXW processthreadsapi SMALLBUSINESS SUITENAME sysinfo sysinfoapi TCHAR TCHARs WCHAR WCHARs winapi winbase winver
// spell-checker:ignore (WinOS) ntdll

use winapi::shared::minwindef::*;
// use winapi::shared::ntdef::NTSTATUS;
// use winapi::shared::ntstatus::*;
// use winapi::um::libloaderapi::*;
use winapi::um::sysinfoapi::*;
// use winapi::um::winbase::*;
use winapi::um::winnt::*;
// use winapi::um::winver::*;

use std::convert::TryFrom;
use std::ffi::CString;
use std::ffi::{OsStr, OsString};
use std::io;
// use std::mem::MaybeUninit;
use std::os::windows::ffi::OsStringExt;
use std::ptr;

use platform_info::*;

// // #[derive(Debug)]
// struct MySystemInfo(SYSTEM_INFO);
// use std::fmt;
// use std::fmt::{Debug, Formatter};

// dwPageSize: DWORD,
// lpMinimumApplicationAddress: LPVOID,
// lpMaximumApplicationAddress: LPVOID,
// dwActiveProcessorMask: DWORD_PTR,
// dwNumberOfProcessors: DWORD,
// dwProcessorType: DWORD,
// dwAllocationGranularity: DWORD,
// wProcessorLevel: WORD,
// wProcessorRevision: WORD,

// impl Debug for MySystemInfo {
//     fn fmt(&self, f: &mut Formatter) -> fmt::Result {
//         unsafe {
//             f.debug_struct("MySystemInfo")
//                 .field(
//                     "wProcessorArchitecture",
//                     &self.0.u.s().wProcessorArchitecture,
//                 )
//                 .field("dwPageSize", &self.0.dwPageSize)
//                 .field(
//                     "lpMinimumApplicationAddress",
//                     &self.0.lpMinimumApplicationAddress,
//                 )
//                 .field(
//                     "lpMaximumApplicationAddress",
//                     &self.0.lpMaximumApplicationAddress,
//                 )
//                 .field("dwActiveProcessorMask", &self.0.dwActiveProcessorMask)
//                 .field("dwNumberOfProcessors", &self.0.dwNumberOfProcessors)
//                 .field("dwProcessorType", &self.0.dwProcessorType)
//                 .field("dwAllocationGranularity", &self.0.dwAllocationGranularity)
//                 .field("wAllocationGranularity", &self.0.wProcessorLevel)
//                 .field("wAllocationRevision", &self.0.wProcessorRevision)
//                 .finish()
//         }
//     }
// }

// #[allow(non_snake_case)]
// fn WinAPI_GetNativeSystemInfo() -> io::Result<SYSTEM_INFO> {
//     let mut sysinfo = MaybeUninit::<SYSTEM_INFO>::uninit();
//     unsafe {
//         GetNativeSystemInfo(sysinfo.as_mut_ptr());
//         // SAFETY: `GetNativeSystemInfo()` always succeeds => `sysinfo` was initialized
//         let sysinfo = sysinfo.assume_init();
//         Ok(sysinfo)
//     }
// }

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
        GetComputerNameExW(ComputerNamePhysicalDnsHostname, ptr::null_mut(), &mut size);
    }

    // println!("size = {}", size);
    let mut data: Vec<WCHAR> = vec![0; usize::try_from(size).unwrap()];
    unsafe {
        if GetComputerNameExW(
            ComputerNameDnsHostname,
            // ComputerNamePhysicalDnsHostname,
            data.as_mut_ptr(),
            &mut size,
        ) != 0
        {
            // ref: https://doc.rust-lang.org/std/os/windows/ffi/index.html
            // ref: [WTF-8/WTF-16](https://simonsapin.github.io/wtf-8/#ill-formed-utf-16)
            // * ??? to use within `rust` String, the data must be converted to well-formed UTF (maybe we could use an OSString)
            // Ok(String::from_utf16_lossy(&data))
            // * note: read ... https://internals.rust-lang.org/t/prerfc-trait-converting-functions-for-osstring/11634/14
            // * read: ... https://users.rust-lang.org/t/tidy-pattern-to-work-with-lpstr-mutable-char-array/2976
            // ??? use a PathBuf?
            println!("{:#?}", data);
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
}

fn into_c_string<T: AsRef<OsStr>>(os_str: T) -> CString {
    let nul = '\0';
    let s = os_str.as_ref().to_string_lossy();
    let leading_s = s.split(nul).next().unwrap_or(""); // leading string with no internal NULs
    match CString::new(leading_s) {
        Ok(s) => s,
        Err(_) => unsafe { CString::from_vec_unchecked(b"".to_vec()) },
    }
}

fn main() {
    let uname = PlatformInfo::new().unwrap();
    // println!("{}", uname.sysname());
    // println!("{}", uname.nodename());
    // println!("{}", uname.release());
    // println!("{}", uname.version());
    // println!("{}", uname.machine());
    // println!("{}", uname.osname());

    println!(
        "result=[{}]'{}'",
        WinAPI_GetComputerNameExW().unwrap().to_string_lossy().len(),
        WinAPI_GetComputerNameExW().unwrap().to_string_lossy()
    );
    let x = uname.system_info;
    println!("result={:#?}", x);

    let s = into_c_string("testing");
    println!("s='{:#?}'", s);
}
