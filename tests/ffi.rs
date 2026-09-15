use std::ffi::CStr;

use keylock::ffi::*;

#[test]
fn c_abi_hashes_and_version_work() {
    let version = unsafe { CStr::from_ptr(keylock_version()) }
        .to_str()
        .unwrap();
    assert_eq!(version, env!("CARGO_PKG_VERSION"));

    let mut sha = [0u8; 32];
    assert!(keylock_sha256(
        b"abc".as_ptr(),
        3,
        sha.as_mut_ptr(),
        sha.len()
    ));
    assert_eq!(
        hex_lower(&sha),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );

    let mut keccak = [0u8; 32];
    assert!(keylock_keccak256(
        b"abc".as_ptr(),
        3,
        keccak.as_mut_ptr(),
        keccak.len()
    ));
    assert_eq!(
        hex_lower(&keccak),
        "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
    );
}

#[test]
fn c_abi_reports_invalid_output_buffer() {
    let mut out = [0u8; 8];
    assert!(!keylock_sha256(
        b"abc".as_ptr(),
        3,
        out.as_mut_ptr(),
        out.len()
    ));
    let error = unsafe { CStr::from_ptr(keylock_last_error_message()) }
        .to_str()
        .unwrap();
    assert!(error.contains("output buffer too small"));
}

#[test]
fn c_abi_random_and_compare_work() {
    let mut out = [0u8; 16];
    assert!(keylock_random_bytes(out.as_mut_ptr(), out.len()));
    assert!(keylock_bytes_equal(
        out.as_ptr(),
        out.len(),
        out.as_ptr(),
        out.len()
    ));
    assert!(!keylock_bytes_equal(
        out.as_ptr(),
        out.len(),
        out.as_ptr(),
        out.len() - 1
    ));
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
