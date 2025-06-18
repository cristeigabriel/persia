// PE structures are picked based on compilation target.
use pelite::{pe::exports::GetProcAddress, pe::*};
use std::{
    fs,
    io::{self},
    result::Result,
};
use winapi::{
    ctypes::c_void,
    shared::{basetsd::SIZE_T, minwindef::DWORD},
    um::{
        errhandlingapi::GetLastError,
        minwinbase::LPTHREAD_START_ROUTINE,
        winnt::{
            IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE,
            IMAGE_SUBSYSTEM_WINDOWS_GUI, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
            PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE, PROCESS_ALL_ACCESS,
        },
    },
};

use crate::util::handle::SafeHandle;

use super::{process, process::ProcessIds};

fn check_same_architecture_as_host(target: &SafeHandle) -> Option<bool> {
    let this = process::current_process();

    let this_wow64 = process::is_wow64(&this)?;
    let target_wow64 = process::is_wow64(target)?;

    Some(this_wow64 == target_wow64)
}

fn validate_pe_and_get_entrypoint(pe: &PeFile<'_>) -> Result<isize, io::Error> {
    // Parse the according optional header
    let subsystem = pe.optional_header().Subsystem;

    match subsystem {
        IMAGE_SUBSYSTEM_WINDOWS_GUI => {}
        _ => {
            println!("[!] invalid pe subsystem...");
            return Err(io::ErrorKind::InvalidData.into());
        }
    }

    println!("[+] passed subsystem check...");

    if let Ok(entrypoint) = pe.get_export("DllMain") {
        return Ok(entrypoint.symbol().map(|x| x as isize).unwrap());
    }

    Err(io::ErrorKind::InvalidData.into())
}

fn get_rwe_from_characteristics(characteristics: u32) -> (bool, bool, bool) {
    let readable = (characteristics & IMAGE_SCN_MEM_READ) != 0;
    let writable = (characteristics & IMAGE_SCN_MEM_WRITE) != 0;
    let executable = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;

    (readable, writable, executable)
}

fn get_page_protection_from_characteristics(characteristics: u32) -> DWORD {
    let (readable, writable, executable) = get_rwe_from_characteristics(characteristics);

    let mut protection_flags = PAGE_NOACCESS;
    if executable && readable && writable {
        protection_flags = PAGE_EXECUTE_READWRITE;
    } else if executable && readable && !writable {
        protection_flags = PAGE_EXECUTE_READ;
    } else if executable && !readable && writable {
        println!("[^] this configuration of flags should be impossible...");
    } else if executable && !readable && !writable {
        protection_flags = PAGE_EXECUTE;
    } else if !executable && readable && writable {
        protection_flags = PAGE_READWRITE;
    } else if !executable && readable && !writable {
        protection_flags = PAGE_READONLY;
    } else if !executable && !readable && writable {
        println!("[^] this configuration of flags should be impossible...");
    }

    protection_flags
}

fn get_page_protection_string_from_characteristics(characteristics: u32) -> String {
    let (readable, writable, executable) = get_rwe_from_characteristics(characteristics);

    let mut protection_str = String::new();
    if readable {
        protection_str += "r";
    }
    if writable {
        protection_str += "w";
    }
    if executable {
        protection_str += "x";
    }

    protection_str
}

pub unsafe fn inject(process: ProcessIds, path: &str) -> Result<(), io::Error> {
    // Lets make sure we have the file first...
    let mut dll_bytes = fs::read(path)?;
    let dll_bytes = dll_bytes.as_mut_slice();

    // Next, lets make sure we can access the process...
    let Some(process) = process::request_handle(process, PROCESS_ALL_ACCESS) else {
        let error = unsafe { GetLastError() as i32 };
        return Err(io::Error::from_raw_os_error(error));
    };

    // Make sure both processes match architecture
    let Some(same_architecture) = check_same_architecture_as_host(&process) else {
        println!("[!] unable to check host/target architecture...");
        return Err(io::ErrorKind::PermissionDenied.into());
    };

    if !same_architecture {
        println!(
            "[!] unable to inject into process of different architecture... please use an appropriate build of the injector"
        );
        return Err(io::ErrorKind::Unsupported.into());
    }

    // Parse PE
    let Ok(pe) = PeFile::from_bytes(dll_bytes) else {
        println!("[!] could not parse pe...");
        return Err(io::ErrorKind::InvalidData.into());
    };

    // Parse entrypoint
    let entrypoint = validate_pe_and_get_entrypoint(&pe)?;

    unsafe {
        // Calculate allocation size for the in-memory representation of the PE file,
        // this could be done in better and more interesting ways, but this is the way my loader chooses to do this for now
        let Some(alloc_size) = pe
            .section_headers()
            .iter()
            .map(|x| x.VirtualAddress + x.VirtualSize)
            .max()
        else {
            return Err(io::ErrorKind::InvalidData.into());
        };

        // Try to allocate memory for the DLL remotely
        let Some(addr) =
            process::remote_allocate(&process, alloc_size as SIZE_T, PAGE_EXECUTE_READWRITE)
        else {
            return Err(io::ErrorKind::PermissionDenied.into());
        };

        // Allocate and set up sections, code
        let sections = pe.section_headers();
        for entry in sections {
            // Section name
            let name = entry.name().ok().unwrap_or("[unnamed]");

            // TODO here: relocations!
            // TODO here: fix imports!

            // Get code slice from disk
            let copy_start = entry.PointerToRawData as usize;
            let mut copy_end = copy_start + entry.SizeOfRawData as usize;

            if entry.SizeOfRawData > entry.VirtualSize {
                // https://stackoverflow.com/questions/28075521/pe-file-sections-sizeofrawdata-or-virtualsize#comment44614130_28075521
                // Sometimes, `SizeOfRawData` is bigger than `VirtualSize` because padding done on the file-system end`

                // Calculate amount of padding bytes and remove from code slice of disk as well
                let padding = (entry.SizeOfRawData - entry.VirtualSize) as usize;
                copy_end -= padding;

                println!(
                    "[+] section {name} disk data larger than memory allocation! will ignore {padding} bytes"
                );
            }
            let copy_slice = &dll_bytes[copy_start..=copy_end];

            // Remote virtual address to allocation, and it's size
            let remote_va = addr.add(entry.VirtualAddress as usize);
            let remote_alloc_size = entry.VirtualSize as usize;

            if entry.VirtualSize > entry.SizeOfRawData {
                // If the allocation is larger than the copy from disk, there may be lingering memory which could lead
                // to weirdness
                if !process::remote_write(
                    &process,
                    remote_va,
                    vec![0u8; remote_alloc_size].as_slice(),
                ) {
                    println!("[!] failed zero-ing {name} allocation...");
                    return Err(io::ErrorKind::PermissionDenied.into());
                }
            }

            if !process::remote_write(&process, remote_va, copy_slice) {
                println!("[!] failed copying {name} section code...");
                return Err(io::ErrorKind::PermissionDenied.into());
            }

            // Process protection flags for the page
            let characteristics = entry.Characteristics;
            let protection_flags = get_page_protection_from_characteristics(characteristics);
            let protection_str = get_page_protection_string_from_characteristics(characteristics);

            if !process::remote_protect(
                &process,
                remote_va,
                remote_alloc_size as SIZE_T,
                protection_flags,
            ) {
                println!("[^] failed changing protection flags for section...");
                continue;
            }

            println!(
                "[+] sucessfully changed protection flags for {name} section to {protection_str} at {remote_va:?} for {remote_alloc_size} bytes"
            );
        }

        // Calculate remote virtual address for entrypoint, and begin remote thread
        let remote_entrypoint_addr: *mut c_void = addr.offset(entrypoint) as *mut c_void;
        let remote_entrypoint_addr =
            std::mem::transmute::<*mut c_void, LPTHREAD_START_ROUTINE>(remote_entrypoint_addr);
        let _ = process::remote_thread(
            &process,
            remote_entrypoint_addr,
            std::ptr::null_mut::<c_void>(),
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use winapi::um::winnt::{
        IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, PAGE_EXECUTE_READ, PAGE_NOACCESS,
    };

    use crate::util::injector::{
        get_page_protection_from_characteristics, get_page_protection_string_from_characteristics,
        get_rwe_from_characteristics,
    };

    const READABLE_EXECUTABLE: u32 = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;

    #[test]
    fn rwe_from_characteristics() {
        let (readable, writable, executable) = get_rwe_from_characteristics(READABLE_EXECUTABLE);

        assert!(readable);
        assert!(!writable);
        assert!(executable);
    }

    #[test]
    fn protection_from_characteristics() {
        let page_protection = get_page_protection_from_characteristics(READABLE_EXECUTABLE);
        let page_noaccess = get_page_protection_from_characteristics(0);

        assert_eq!(page_protection, PAGE_EXECUTE_READ);
        assert_eq!(page_noaccess, PAGE_NOACCESS);
    }

    #[test]
    fn rwe_string_from_characteristics() {
        let rwe = get_page_protection_string_from_characteristics(READABLE_EXECUTABLE);

        assert_eq!(rwe, "rx");
    }
}
