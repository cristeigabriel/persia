use std::ptr;
use winapi::um::{
    handleapi::{CloseHandle, INVALID_HANDLE_VALUE},
    winnt::HANDLE,
};

#[derive(Debug)]
/// Safe Windows `HANDLE` representation.
///
/// Provides routines to check the wellness of a handle, and is responsible to clean up the handle
/// once it is no longer required through the `Drop` trait.
///
/// TODO: implement `Clone` trait.
pub struct SafeHandle {
    handle: HANDLE,
    /// This distinction is important, and could also be held at the type level rather.
    /// In scenarios of files (but not exclusively), a failed attempt to obtain a `HANDLE`
    /// could result in `INVALID_HANDLE_VALUE`, but, for example, in the scenario of pseudo-handles,
    /// such as the one retrieved from `GetCurrentProcess`, it returns `-1`, equivalent to `~0`, equivalent
    /// to `0xFFFFFFFF``, which is the same as `INVALID_HANDLE_VALUE`.
    file: bool,
}

impl SafeHandle {
    pub fn from(handle: HANDLE) -> SafeHandle {
        Self {
            handle,
            file: false,
        }
    }

    pub fn from_file(handle: HANDLE) -> SafeHandle {
        Self { handle, file: true }
    }

    pub fn get(&self) -> HANDLE {
        self.handle
    }

    /// Check if the handle has the value of `NULL` or `INVALID_HANDLE_VALUE` (in the case of files).
    pub fn is_bad(&self) -> bool {
        if self.handle.is_null() {
            return true;
        }

        if self.file && self.handle == INVALID_HANDLE_VALUE {
            return true;
        }

        false
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
