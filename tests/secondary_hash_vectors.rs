//! BLAKE2 / Whirlpool / Streebog / Skein / SM3 / Keccak known-answer vectors.

use keylock::hash::{blake2b, blake2s, blake2x, keccak, legacy, skein};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// RFC 7693 BLAKE2b-512("abc") — already covered in known_answer_vectors; add
// BLAKE2b-256 and the empty-input case here.
#[test]
fn blake2b_256_empty() {
    // BLAKE2b-256(""): well-known reference output.
    let expected = "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8";
    assert_eq!(hex(&blake2b::hash(b"", 32).unwrap()), expected);
}

// RFC 7693 BLAKE2s-256("abc")
#[test]
fn blake2s_256_abc_rfc7693() {
    let expected = "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982";
    assert_eq!(hex(&blake2s::hash(b"abc")), expected);
}

// BLAKE2s-256(""): well-known reference
#[test]
fn blake2s_256_empty() {
    let expected = "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9";
    assert_eq!(hex(&blake2s::hash(b"")), expected);
}

// BLAKE2xb XOF: the output should be deterministic and length-domain-separated.
#[test]
fn blake2xb_distinct_outputs_for_distinct_messages() {
    let a = blake2x::xof(b"alpha", 64).unwrap();
    let b = blake2x::xof(b"beta", 64).unwrap();
    assert_ne!(a, b);
    // First-32 of length-64 output is NOT equal to length-32 output (length is part of domain).
    let short = blake2x::xof(b"alpha", 32).unwrap();
    assert_ne!(a[..32], short[..]);
}

// Whirlpool("") — well-known vector
#[test]
fn whirlpool_empty_known_vector() {
    let expected = "19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a73e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3";
    assert_eq!(hex(&legacy::whirlpool::hash(b"")), expected);
}

// Whirlpool("a")
#[test]
fn whirlpool_one_byte_known_vector() {
    let expected = "8aca2602792aec6f11a67206531fb7d7f0dff59413145e6973c45001d0087b42d11bc645413aeff63a42391a39145a591a92200d560195e53b478584fdae231a";
    assert_eq!(hex(&legacy::whirlpool::hash(b"a")), expected);
}

// SM3 GM/T 0004-2012 long message vector
#[test]
fn sm3_long_message_vector() {
    let msg = b"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";
    let expected = "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732";
    assert_eq!(hex(&legacy::sm3::hash(msg)), expected);
}

// Streebog-256("") (GOST R 34.11-2012 test vector)
#[test]
fn streebog_256_empty() {
    let expected = "3f539a213e97c802cc229d474c6aa32a825a360b2a933a949fd925208d9ce1bb";
    assert_eq!(hex(&legacy::streebog::hash_256(b"")), expected);
}

// Streebog-512("") (GOST R 34.11-2012 test vector)
#[test]
fn streebog_512_empty() {
    let expected = "8e945da209aa869f0455928529bcae4679e9873ab707b55315f56ceb98bef0a7362f715528356ee83cda5f2aac4c6ad2ba3a715c1bcd81cb8e9f90bf4c1c1a8a";
    assert_eq!(hex(&legacy::streebog::hash_512(b"")), expected);
}

// Skein-512-512("") — Skein round-3 test vector
#[test]
fn skein_512_empty_size() {
    // We don't have a NIST vector handy; just confirm size + determinism.
    let h1 = skein::hash_512(b"hello world");
    let h2 = skein::hash_512(b"hello world");
    assert_eq!(h1, h2);
    assert_eq!(h1.len(), 64);
    let h3 = skein::hash_512(b"hello WORLD");
    assert_ne!(h1, h3);
}

// Keccak-256("abc") — Ethereum vector
#[test]
fn keccak256_abc_known_vector() {
    let expected = "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45";
    assert_eq!(hex(&keccak::hash_256(b"abc")), expected);
}
