//! AES known-answer vectors from FIPS 197 and NIST SP 800-38A.

use keylock::crypto::aes;

fn hex_bytes(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i + 1 < bytes.len() {
        let h = char::from(bytes[i]).to_digit(16).unwrap() as u8;
        let l = char::from(bytes[i + 1]).to_digit(16).unwrap() as u8;
        out.push((h << 4) | l);
        i += 2;
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// FIPS 197 §C.1 — AES-128 single-block known answer.
#[test]
fn aes128_fips197_appendix_c1() {
    let key = hex_bytes("000102030405060708090a0b0c0d0e0f");
    let plaintext = hex_bytes("00112233445566778899aabbccddeeff");
    let expected = "69c4e0d86a7b0430d8cdb78070b4c55a";

    let ctx = aes::init(&key);
    let ct = aes::encrypt_block(&ctx, &plaintext);
    assert_eq!(hex(&ct), expected);
    let pt = aes::decrypt_block(&ctx, &ct);
    assert_eq!(pt, plaintext);
}

// FIPS 197 §C.3 — AES-256 single-block known answer.
#[test]
fn aes256_fips197_appendix_c3() {
    let key = hex_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    let plaintext = hex_bytes("00112233445566778899aabbccddeeff");
    let expected = "8ea2b7ca516745bfeafc49904b496089";

    let ctx = aes::init(&key);
    let ct = aes::encrypt_block(&ctx, &plaintext);
    assert_eq!(hex(&ct), expected);
    assert_eq!(aes::decrypt_block(&ctx, &ct), plaintext);
}

// NIST SP 800-38A §F.5.5 — CTR-AES256 single-block.
// Key: 603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4
// Counter: f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
// Plaintext blk 1: 6bc1bee22e409f96e93d7e117393172a
// Ciphertext blk 1: 601ec313775789a5b7a7f504bbf3d228
#[test]
fn aes256_ctr_nist_sp800_38a_first_block() {
    let key = hex_bytes("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
    let nonce = hex_bytes("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    let plaintext = hex_bytes("6bc1bee22e409f96e93d7e117393172a");
    let expected = "601ec313775789a5b7a7f504bbf3d228";

    let ctx = aes::init(&key);
    let ct = aes::ctr_crypt(&ctx, &nonce, &plaintext);
    assert_eq!(hex(&ct), expected);
    assert_eq!(aes::ctr_crypt(&ctx, &nonce, &ct), plaintext);
}

// NIST SP 800-38A §F.2.5 — CBC-AES256 first block.
// IV: 000102030405060708090a0b0c0d0e0f
// Plaintext blk 1: 6bc1bee22e409f96e93d7e117393172a
// Ciphertext blk 1: f58c4c04d6e5f1ba779eabfb5f7bfbd6
#[test]
fn aes256_cbc_nist_sp800_38a_first_block() {
    let key = hex_bytes("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
    let iv = hex_bytes("000102030405060708090a0b0c0d0e0f");
    let plaintext = hex_bytes("6bc1bee22e409f96e93d7e117393172a");
    let expected = "f58c4c04d6e5f1ba779eabfb5f7bfbd6";

    let ctx = aes::init(&key);
    let ct = aes::cbc_encrypt(&ctx, &iv, &plaintext);
    assert_eq!(hex(&ct), expected);
    assert_eq!(aes::cbc_decrypt(&ctx, &iv, &ct), plaintext);
}
