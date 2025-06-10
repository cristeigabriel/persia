use pe_parser::{
    optional::{Optional, Subsystem},
    pe::{PortableExecutable, parse_portable_executable},
    section::SectionFlags,
};
use std::{fs, io, result::Result};
use winapi::{
    ctypes::c_void,
    shared::minwindef::DWORD,
    um::{
        errhandlingapi::GetLastError, minwinbase::LPTHREAD_START_ROUTINE, winnt::{
            PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
            PAGE_READONLY, PAGE_READWRITE, PROCESS_ALL_ACCESS,
        }
    },
};

use super::{process, process::ProcessIds};

fn validate_pe_and_get_entrypoint(pe: &PortableExecutable) -> Result<Option<isize>, io::Error> {
    // Parse the according optional header
    let mut subsystem: Option<Subsystem> = None;
    let mut entrypoint: Option<isize> = None;

    if let Some(optional_header) = pe.optional_header_32 {
        subsystem = optional_header.get_subsystem();
        entrypoint = Some(optional_header.address_of_entry_point as isize);
    } else if let Some(optional_header) = pe.optional_header_64 {
        subsystem = optional_header.get_subsystem();
        entrypoint = Some(optional_header.address_of_entry_point as isize);
    } else {
        println!("[!] could not parse optional header...");
        return Err(io::ErrorKind::InvalidData.into());
    }

    if let Some(subsystem) = subsystem {
        match subsystem {
            Subsystem::WindowsGUI => {}
            _ => {
                println!("[!] invalid pe subsystem...");
                return Err(io::ErrorKind::InvalidData.into());
            }
        }
    } else {
        println!("[!] could not parse pe subsystem...");
        return Err(io::ErrorKind::InvalidData.into());
    }

    println!("[+] passed subsystem check...");

    Ok(entrypoint)
}

fn get_rwe_from_characteristics(characteristics: &SectionFlags) -> (bool, bool, bool) {
    let characteristics = characteristics.bits();

    let readable = (characteristics & SectionFlags::IMAGE_SCN_MEM_READ.bits()) != 0;
    let writable = (characteristics & SectionFlags::IMAGE_SCN_MEM_WRITE.bits()) != 0;
    let executable = (characteristics & SectionFlags::IMAGE_SCN_MEM_EXECUTE.bits()) != 0;

    (readable, writable, executable)
}

fn get_page_protection_from_characteristics(characteristics: &SectionFlags) -> DWORD {
    let (readable, writable, executable) = get_rwe_from_characteristics(characteristics);

    let mut protection_flags: DWORD = 0;
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

fn get_page_protection_string_from_characteristics(characteristics: &SectionFlags) -> String {
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

    return protection_str;
}

pub unsafe fn inject(process: ProcessIds, path: &str) -> Result<(), io::Error> {
    // Lets make sure we have the file first...
    let dll_bytes = fs::read(path)?;

    // Next, lets make sure we can access the process...
    let Some(process) = process::request_handle(PROCESS_ALL_ACCESS, process) else {
        let error = unsafe { GetLastError() as i32 };
        return Err(io::Error::from_raw_os_error(error));
    };

    // Parse PE
    let Ok(pe) = parse_portable_executable(&dll_bytes.as_slice()) else {
        println!("[!] could not parse pe...");
        return Err(io::ErrorKind::InvalidData.into());
    };

    // Parse entrypoint
    let Some(entrypoint) = validate_pe_and_get_entrypoint(&pe)? else {
        println!("[!] could not identify entrypoint...");
        return Err(io::ErrorKind::NotFound.into());
    };

    unsafe {
        // Try to allocate memory for the DLL remotely
        let Some(addr) = process::remote_allocate(&process, dll_bytes.len(), PAGE_EXECUTE_READWRITE) else {
            return Err(io::ErrorKind::PermissionDenied.into());
        };

        println!("[+] allocated memory in process... {:x}", addr as usize);

        // Write DLL to memory
        if !process::remote_write(&process, addr, &dll_bytes[..]) {
            return Err(io::ErrorKind::PermissionDenied.into());
        }

        println!("[+] succesfully written dll to memory...");

        // Update page protections
        let sections = pe.section_table;
        for entry in sections {
            // Section name
            let name = entry
                .get_name()
                .or_else(|| Some("[unnamed!]".to_owned()))
                .unwrap();

            // Get characteristics
            let Some(characteristics) = entry.get_characteristics() else {
                println!("[^] section {name} doesn't have characteristics...");
                continue;
            };

            let protection_flags = get_page_protection_from_characteristics(&characteristics);
            let protection_str = get_page_protection_string_from_characteristics(&characteristics);

            // Get start relative virtual address and size of section
            let rva = entry.pointer_to_raw_data as isize;
            let size = entry.size_of_raw_data as usize;

            // Get remote pointer to section
            let remote_va = (addr as *mut u8).offset(rva) as *mut c_void;

            if !process::remote_protect(&process, remote_va, size, PAGE_EXECUTE_READWRITE) {
                println!("[^] failed changing protection flags for section...");
                continue;
            }

            println!(
                "[+] sucessfully changed protection flags for {name} section to {protection_str} at {:x} for {size} bytes",
                remote_va as usize
            );
        }

        // TODO: relocations!

        // Start preparing to create remote thread
        let entrypoint_addr = (addr as *mut u8).offset(entrypoint) as *mut c_void;
        let entrypoint_addr = std::mem::transmute::<*mut c_void, LPTHREAD_START_ROUTINE>(entrypoint_addr);
        let handle = unsafe { process::remote_thread(&process, entrypoint_addr, std::ptr::null_mut()) };
        if let Some(mut handle) = handle {
            handle.close();
        }
    }

    Ok(())
}
