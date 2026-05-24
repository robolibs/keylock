//! Constant-time comparison and wiping helpers matching the keylock C++ header
//! hierarchy while delegating the sensitive primitives to Rust ecosystem crates.

pub mod verify;
pub mod wipe;

pub use verify::{secure_compare, verify, verify16, verify32, verify64};
pub use wipe::{wipe, wipe_container};
