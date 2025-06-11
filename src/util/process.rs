use super::handle::SafeHandle;
use std::vec::Vec;
use winapi::{
    ctypes::c_void,
    shared::{basetsd::SIZE_T, minwindef::DWORD},
    um::{
        errhandlingapi::{GetLastError, SetLastError},
        memoryapi::{VirtualAllocEx, VirtualProtectEx, WriteProcessMemory},
        minwinbase::LPTHREAD_START_ROUTINE,
        processthreadsapi::{CreateRemoteThread, OpenProcess},
        psapi::{EnumProcesses, GetModuleBaseNameA},
        winnt::{LPSTR, MEM_COMMIT, MEM_TOP_DOWN, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ},
    },
};

/// Warning: Because of the way EnumProcesses works,
/// it'll only catch a maximum of the first 1024 processes
/// running, in order, on the system.
///
/// EnumProcesses will not tell you if you need more bytes than
/// you initially provided. To really check, you'd need a loop of reallocating.
/// Surprisingly, I've yet to see this being documented anywhere besides ReactOS.
fn get_all_processes() -> Vec<u32> {
    let mut pids: Vec<DWORD> = vec![0; 1024];
    let mut bytes_needed = (pids.len() * std::mem::size_of::<DWORD>()) as DWORD;
    let bytes_current = bytes_needed;

    // The following operation should be safe because:
    // - Vector is expected to be DWORD-aligned (32 bit)
    // - Data is expected to be contiguous
    // Therefore, it should fit the layout requirement for `EnumProcesses`

    if unsafe {
        EnumProcesses(
            pids.as_mut_ptr(),
            bytes_current,
            (&mut bytes_needed) as *mut DWORD,
        )
    } == 0
        || bytes_needed == 0
    {
        return vec![];
    }

    // Shrink the vector to the minimum size
    let min_size = bytes_needed as usize / std::mem::size_of::<DWORD>();
    if min_size > pids.len() {
        return vec![];
    }

    // Truncate pids list and shrink capacity (truncate does not)
    pids.truncate(min_size);
    pids.shrink_to(min_size);
    pids
}

fn find_process_pid_by_name(name: &str) -> Option<u32> {
    let pids = get_all_processes();
    if pids.is_empty() {
        return None;
    }

    let mut names = pids
        .into_iter()
        .map(|pid| {
            let handle = request_handle(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                ProcessIds::Pid(pid),
            );
            (pid, handle)
        })
        .filter(|(_, x)| x.is_some() && !x.as_ref().unwrap().is_bad())
        .map(|(pid, x)| {
            let mut name = [0u8; 260];
            let ret = unsafe {
                GetModuleBaseNameA(
                    x.unwrap().get(),
                    std::ptr::null_mut(),
                    name.as_mut_ptr() as LPSTR,
                    name.len() as u32,
                ) as usize
            };
            let error = unsafe { GetLastError() };
            name[ret] = 0;
            (pid, name, ret, error)
        })
        .filter(|(_, _, ret, error)| *error == 0 || *ret != 0);

    let pid = names
        .find(|(_, entry, len, _)| {
            str::from_utf8(&entry[..*len]).unwrap().to_lowercase() == name.to_lowercase()
        })
        .into_iter()
        .map(|(pid, _, _, _)| pid)
        .next();
    pid
}

#[derive(Debug)]
pub enum ProcessIds<'a> {
    Name(&'a str),
    Pid(u32),
}

impl<'a> ProcessIds<'a> {
    pub fn get_os_pid(&'a self) -> Option<u32> {
        match *self {
            ProcessIds::Pid(pid) => Some(pid),
            ProcessIds::Name(name) => find_process_pid_by_name(name),
        }
    }
}

pub fn request_handle(desired_access: DWORD, process: ProcessIds<'_>) -> Option<SafeHandle> {
    let pid = process.get_os_pid()?;
    let process = SafeHandle::from(unsafe { OpenProcess(desired_access, 0, pid).into() });
    let error = unsafe { GetLastError() };
    if error != 0 {
        unsafe { SetLastError(0) };
        return None;
    }
    if process.is_bad() {
        return None;
    }

    Some(process)
}

pub unsafe fn remote_allocate(
    process: &SafeHandle,
    size: SIZE_T,
    protect: DWORD,
) -> Option<*mut u8> {
    if process.is_bad() {
        return None;
    }

    let ptr = unsafe {
        VirtualAllocEx(
            process.get(),
            std::ptr::null_mut(),
            size,
            MEM_COMMIT | MEM_TOP_DOWN,
            protect,
        )
    } as *mut u8;
    if ptr.is_null() {
        return None;
    }

    let error = unsafe { GetLastError() };
    if error != 0 {
        return None;
    }

    Some(ptr)
}

pub unsafe fn remote_write<T>(process: &SafeHandle, address: *mut T, buffer: &[u8]) -> bool {
    if process.is_bad() {
        return false;
    }

    let mut written_bytes: SIZE_T = 0;
    let ret = unsafe {
        WriteProcessMemory(
            process.get(),
            address as _,
            buffer.as_ptr() as _,
            buffer.len(),
            &mut written_bytes,
        )
    };

    let error = unsafe { GetLastError() };
    if ret == 0 || error != 0 {
        unsafe { SetLastError(0) };
        return false;
    }

    if written_bytes != buffer.len() {
        return false;
    }

    true
}

pub unsafe fn remote_protect<T>(
    process: &SafeHandle,
    address: *mut T,
    size: SIZE_T,
    protect_flags: DWORD,
) -> bool {
    if process.is_bad() {
        return false;
    }

    let mut old_protect: DWORD = 0;
    let ret = unsafe {
        VirtualProtectEx(
            process.get(),
            address as _,
            size,
            protect_flags,
            &mut old_protect,
        )
    };

    let error = unsafe { GetLastError() };
    if ret == 0 || error != 0 {
        unsafe { SetLastError(0) };
        return false;
    }

    true
}

pub unsafe fn remote_thread<T>(
    process: &SafeHandle,
    start_address: LPTHREAD_START_ROUTINE,
    parameter: *mut T,
) -> Option<SafeHandle> {
    if process.is_bad() {
        return None;
    }

    let ret = SafeHandle::from(unsafe {
        CreateRemoteThread(
            process.get(),
            std::ptr::null_mut(),
            0,
            start_address,
            parameter as _,
            0,
            std::ptr::null_mut(),
        )
    });

    let error = unsafe { GetLastError() };
    if ret.is_bad() || error != 0 {
        unsafe { SetLastError(0) };
        return None;
    }

    Some(ret)
}
