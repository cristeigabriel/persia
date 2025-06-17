use std::ptr;
use winapi::um::{
    handleapi::{CloseHandle, INVALID_HANDLE_VALUE},
    winnt::HANDLE,
};

#[repr(C)]
#[repr(packed(1))]
#[derive(Debug)]
/// Safe Windows `HANDLE` representation.
/// 
/// Provides routines to check the wellness of a handle, and is responsible to clean up the handle
/// once it is no longer required through the `Drop` trait.
/// 
/// TODO: implement `Clone` trait.
pub struct SafeHandle {
    handle: HANDLE,
}

impl SafeHandle {
    pub fn from(handle: HANDLE) -> SafeHandle {
        Self { handle }
    }

    pub fn get(&self) -> HANDLE {
        self.handle
    }

    /// Check if the handle has the value of `NULL` or `INVALID_HANDLE_VALUE`.
    pub fn is_bad(&self) -> bool {
        self.handle.is_null() || self.handle == INVALID_HANDLE_VALUE
    }

    /// If the handle is valid, use `CloseHandle` to dispose of it inside the process
    /// handle table, and then mark that it has been closed.
    pub fn close(&mut self) {
        if !self.is_bad() {
            unsafe { CloseHandle(self.handle) };
        }

        self.handle = ptr::null_mut();
    }
}

impl std::ops::Drop for SafeHandle {
    fn drop(&mut self) {
        self.close()
    }
}
