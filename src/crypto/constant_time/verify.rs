//! Constant-time equality helpers for the C++ `crypto/constant_time/verify.hpp`
//! surface.

use subtle::ConstantTimeEq;

fn result_from_choice(equal: subtle::Choice) -> i32 {
    if equal.unwrap_u8() == 1 { 0 } else { -1 }
}

/// Compare two same-length byte slices in constant time.
///
/// Returns `0` when equal and `-1` otherwise, matching the libsodium-shaped
/// C++ keylock helper surface.
pub fn verify(a: &[u8], b: &[u8]) -> i32 {
    if a.len() != b.len() {
        return -1;
    }
    result_from_choice(a.ct_eq(b))
}

/// Compare 16 bytes in constant time.
pub fn verify16(a: &[u8; 16], b: &[u8; 16]) -> i32 {
    result_from_choice(a.ct_eq(b))
}

/// Compare 32 bytes in constant time.
pub fn verify32(a: &[u8; 32], b: &[u8; 32]) -> i32 {
    result_from_choice(a.ct_eq(b))
}

/// Compare 64 bytes in constant time.
pub fn verify64(a: &[u8; 64], b: &[u8; 64]) -> i32 {
    result_from_choice(a.ct_eq(b))
}

/// Constant-time equality with a boolean result.
pub fn secure_compare(a: &[u8], b: &[u8]) -> bool {
    verify(a, b) == 0
}
