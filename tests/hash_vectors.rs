//! Hash known-answer vectors.

use keylock::hash::{
    HashAlgorithm, hkdf, hmac_sha256, hmac_sha384, hmac_sha512, kmac, sha256, sha3, sha512, shake,
};

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

// FIPS 180-4: SHA-256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
#[test]
fn sha256_fips180_two_block_message() {
    let msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    let expected = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";
    assert_eq!(hex(&sha256::hash(msg)), expected);
}

// FIPS 180-4: SHA-512("abc")
#[test]
fn sha512_fips180_abc() {
    let expected = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
    assert_eq!(hex(&sha512::hash(b"abc")), expected);
}

// FIPS 202: SHA3-512("")
#[test]
fn sha3_512_fips202_empty() {
    let expected = "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26";
    assert_eq!(hex(&sha3::hash_512(b"")), expected);
}

// FIPS 202: SHAKE128(M="", L=32)
#[test]
fn shake128_fips202_empty_short() {
    let expected = "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26";
    assert_eq!(hex(&shake::shake128(b"", 32)), expected);
}

// FIPS 202: SHAKE256(M="", L=32)
#[test]
fn shake256_fips202_empty_short() {
    let expected = "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f";
    assert_eq!(hex(&shake::shake256(b"", 32)), expected);
}

// RFC 4231 — HMAC-SHA-256 test case 1 (key 20× 0x0b, data "Hi There")
#[test]
fn hmac_sha256_rfc4231_test_case_1() {
    let key = [0x0bu8; 20];
    let data = b"Hi There";
    let expected = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";
    assert_eq!(hex(&hmac_sha256::hmac(&key, data)), expected);
}

// RFC 4231 — HMAC-SHA-384 test case 2 (key "Jefe", data "what do ya want for nothing?")
#[test]
fn hmac_sha384_rfc4231_test_case_2() {
    let key = b"Jefe";
    let data = b"what do ya want for nothing?";
    let expected = "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649";
    assert_eq!(hex(&hmac_sha384::hmac(key, data)), expected);
}

// RFC 4231 — HMAC-SHA-512 test case 1
#[test]
fn hmac_sha512_rfc4231_test_case_1() {
    let key = [0x0bu8; 20];
    let data = b"Hi There";
    let expected = "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854";
    assert_eq!(hex(&hmac_sha512::hmac(&key, data)), expected);
}

// RFC 5869 HKDF-SHA-256 test vector 2 (longer input)
#[test]
fn hkdf_sha256_rfc5869_test_vector_2() {
    let ikm = hex_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f");
    let salt = hex_bytes("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
    let info = hex_bytes("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    let expected_okm = "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87";
    let result = hkdf::hkdf(HashAlgorithm::Sha256, &ikm, &salt, &info, 82);
    assert!(result.success);
    assert_eq!(hex(&result.data), expected_okm);
}

// NIST KMAC128 sample 1 (Key, Data, KMAC128(L=256))
// Key:  404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f
// Data: 00010203
// S:    "" (empty customisation)
// Expected: e5780b0d3ea6f7d3a429c5706aa43a00fadbd7d49628839e3187243f456ee14e
#[test]
fn kmac128_nist_sample_1() {
    let key = hex_bytes("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");
    let data = hex_bytes("00010203");
    let expected = "e5780b0d3ea6f7d3a429c5706aa43a00fadbd7d49628839e3187243f456ee14e";
    let out = kmac::kmac128(&key, b"", &data, 32);
    assert_eq!(hex(&out), expected);
}

// NIST KMAC256 sample 1 (Key, Data, KMAC256(L=512))
// Data: 00010203
// S:    "My Tagged Application"
#[test]
fn kmac256_nist_sample_1() {
    let key = hex_bytes("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");
    let data = hex_bytes("00010203");
    let custom = b"My Tagged Application";
    let expected = "20c570c31346f703c9ac36c61c03cb64c3970d0cfc787e9b79599d273a68d2f7f69d4cc3de9d104a351689f27cf6f5951f0103f33f4f24871024d9c27773a8dd";
    let out = kmac::kmac256(&key, custom, &data, 64);
    assert_eq!(hex(&out), expected);
}
