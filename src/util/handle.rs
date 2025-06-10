use std::ptr;
use winapi::um::{
    handleapi::{CloseHandle, INVALID_HANDLE_VALUE},
    winnt::HANDLE,
};

#[repr(C)]
#[repr(packed(1))]
#[derive(Debug)]
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

    pub fn is_bad(&self) -> bool {
        self.handle.is_null() || self.handle == INVALID_HANDLE_VALUE
    }

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
