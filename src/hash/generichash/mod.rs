//! Libsodium-shaped generic hash compatibility surface.
//!
//! The C++ `keylock/hash/generichash/blake2b_keyed.hpp` header exposes
//! `crypto_generichash`-style helpers backed by BLAKE2b.  Keep that hierarchy
//! in Rust, but delegate the primitive to the RustCrypto `blake2` crate.

pub mod blake2b_keyed;

pub use blake2b_keyed::{
    BYTES, BYTES_MAX, BYTES_MIN, Context, KEYBYTES, KEYBYTES_MAX, KEYBYTES_MIN, final_bytes,
    generichash, generichash_keyed, hash, hash_keyed, init, init_with_key, keyed_init, update,
};
