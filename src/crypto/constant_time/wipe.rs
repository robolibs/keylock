//! Secure wiping helpers for the C++ `crypto/constant_time/wipe.hpp` surface.

use core::sync::atomic::{Ordering, compiler_fence};
use zeroize::Zeroize;

/// Securely zero a mutable byte slice.
pub fn wipe(secret: &mut [u8]) {
    secret.zeroize();
    compiler_fence(Ordering::SeqCst);
}

/// Securely zero a zeroize-capable container such as `Vec<u8>` or a fixed
/// array, matching the C++ `wipe_container` intent without hand-rolled volatile
/// loops.
pub fn wipe_container<T: Zeroize + ?Sized>(container: &mut T) {
    container.zeroize();
    compiler_fence(Ordering::SeqCst);
}
