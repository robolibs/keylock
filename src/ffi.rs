//! C ABI for keylock.
//!
//! Conventions: opaque Box-backed handles (free with the matching
//! *_free); fallible calls return bool/int with the reason in the
//! thread-local keylock_last_error_message(); byte views borrow caller
//! memory and output bytes are written into caller-owned buffers.
//!
//! `include/keylock.h` is generated from this file by cbindgen.

// extern "C" fns take raw pointers from C and deref them by design.
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::cell::RefCell;
use std::ffi::{CString, c_char};
use std::ptr;

thread_local! {
    static LAST_ERROR: RefCell<Option<CString>> = const { RefCell::new(None) };
}

fn clear_last_error() {
    LAST_ERROR.with(|slot| *slot.borrow_mut() = None);
}

fn set_last_error(message: impl Into<String>) {
    let message = message.into().replace('\0', " ");
    LAST_ERROR.with(|slot| {
        *slot.borrow_mut() = Some(
            CString::new(message).unwrap_or_else(|_| CString::new("keylock ffi error").unwrap()),
        );
    });
}

unsafe fn bytes_in<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if len == 0 {
        return Some(&[]);
    }
    if ptr.is_null() {
        set_last_error("null input pointer with nonzero length");
        return None;
    }
    Some(unsafe { std::slice::from_raw_parts(ptr, len) })
}

unsafe fn bytes_out<'a>(ptr: *mut u8, len: usize, expected: usize) -> Option<&'a mut [u8]> {
    if ptr.is_null() {
        set_last_error("null output pointer");
        return None;
    }
    if len < expected {
        set_last_error(format!("output buffer too small: need {expected} bytes"));
        return None;
    }
    Some(unsafe { std::slice::from_raw_parts_mut(ptr, expected) })
}

/// Borrowed byte view used by the C ABI.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct KeylockBytes {
    pub ptr: *const u8,
    pub len: usize,
}

/// Returns a pointer to the last error message, or NULL if there is none.
/// The pointer is valid until the next FFI call on this thread.
#[unsafe(no_mangle)]
pub extern "C" fn keylock_last_error_message() -> *const c_char {
    LAST_ERROR.with(|slot| {
        slot.borrow()
            .as_ref()
            .map_or(ptr::null(), |message| message.as_ptr())
    })
}

/// Crate version, as a static NUL-terminated string.
#[unsafe(no_mangle)]
pub extern "C" fn keylock_version() -> *const c_char {
    static VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "\0");
    VERSION.as_ptr().cast()
}

/// Fill `out` with cryptographically secure random bytes.
#[unsafe(no_mangle)]
pub extern "C" fn keylock_random_bytes(out: *mut u8, out_len: usize) -> bool {
    clear_last_error();
    if out_len == 0 {
        return true;
    }
    if out.is_null() {
        set_last_error("null output pointer");
        return false;
    }
    let out = unsafe { std::slice::from_raw_parts_mut(out, out_len) };
    match crate::crypto::rng::randombytes_buf(out) {
        Ok(()) => true,
        Err(error) => {
            set_last_error(error);
            false
        }
    }
}

/// Uniform random `u32` in `[0, upper_bound)`, or 0 when `upper_bound < 2`.
#[unsafe(no_mangle)]
pub extern "C" fn keylock_random_uniform(upper_bound: u32) -> u32 {
    clear_last_error();
    crate::crypto::rng::randombytes_uniform(upper_bound)
}

/// Compute SHA-256 into a caller-owned 32-byte output buffer.
#[unsafe(no_mangle)]
pub extern "C" fn keylock_sha256(
    input: *const u8,
    input_len: usize,
    out: *mut u8,
    out_len: usize,
) -> bool {
    clear_last_error();
    let Some(input) = (unsafe { bytes_in(input, input_len) }) else {
        return false;
    };
    let Some(out) = (unsafe { bytes_out(out, out_len, crate::hash::sha256::BYTES) }) else {
        return false;
    };
    out.copy_from_slice(&crate::hash::sha256::hash(input));
    true
}

/// Compute Keccak-256 into a caller-owned 32-byte output buffer.
#[unsafe(no_mangle)]
pub extern "C" fn keylock_keccak256(
    input: *const u8,
    input_len: usize,
    out: *mut u8,
    out_len: usize,
) -> bool {
    clear_last_error();
    let Some(input) = (unsafe { bytes_in(input, input_len) }) else {
        return false;
    };
    let Some(out) = (unsafe { bytes_out(out, out_len, 32) }) else {
        return false;
    };
    out.copy_from_slice(&crate::keccak256(input));
    true
}

/// Constant-time byte equality. Returns false for null pointers with nonzero length.
#[unsafe(no_mangle)]
pub extern "C" fn keylock_bytes_equal(
    a: *const u8,
    a_len: usize,
    b: *const u8,
    b_len: usize,
) -> bool {
    clear_last_error();
    let Some(a) = (unsafe { bytes_in(a, a_len) }) else {
        return false;
    };
    let Some(b) = (unsafe { bytes_in(b, b_len) }) else {
        return false;
    };
    if a.len() != b.len() {
        return false;
    }
    crate::crypto::constant_time::secure_compare(a, b)
}
