//! Cryptographically-secure RNG compatibility surface.
//!
//! Mirrors `keylock/crypto/rng/randombytes.hpp`. Delegates to OS randomness via
//! the `getrandom` crate.

pub fn randombytes_buf(buf: &mut [u8]) -> Result<(), String> {
    getrandom::getrandom(buf).map_err(|e| e.to_string())
}

/// Returns a uniformly random `u32` in `[0, upper_bound)`. Matches the
/// libsodium / keylock-cpp semantics: returns 0 if `upper_bound == 0`.
pub fn randombytes_uniform(upper_bound: u32) -> u32 {
    if upper_bound < 2 {
        return 0;
    }
    // Rejection sampling to avoid modulo bias.
    let mut buf = [0u8; 4];
    let min = upper_bound.wrapping_neg() % upper_bound;
    loop {
        if getrandom::getrandom(&mut buf).is_err() {
            return 0;
        }
        let r = u32::from_le_bytes(buf);
        if r >= min {
            return r % upper_bound;
        }
    }
}

pub fn random_u32() -> u32 {
    let mut buf = [0u8; 4];
    getrandom::getrandom(&mut buf).ok();
    u32::from_le_bytes(buf)
}
