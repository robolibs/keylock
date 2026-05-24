//! Argon2 known-answer vectors and negative tests.

use keylock::kdf::argon2 as kargon2;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// RFC 9106 §5.1 — Argon2d test vector with associated_data.
// Parameters: password=01×32, salt=02×16, secret=03×8, AD=04×12,
//             memory=32 KiB (32 blocks), passes=3, parallelism=4, taglen=32
#[test]
fn argon2d_rfc9106_section_5_1() {
    let password = [0x01u8; 32];
    let salt = [0x02u8; 16];
    let secret = [0x03u8; 8];
    let ad = [0x04u8; 12];
    let expected = "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb";

    let result = kargon2::derive_with_extras(
        &password,
        &salt,
        &secret,
        &ad,
        kargon2::Config {
            algorithm: kargon2::Algorithm::Argon2d,
            nb_blocks: 32,
            nb_passes: 3,
            nb_lanes: 4,
        },
        32,
    )
    .unwrap();
    assert_eq!(hex(&result), expected);
}

// RFC 9106 §5.2 — Argon2i test vector with associated_data
#[test]
fn argon2i_rfc9106_section_5_2() {
    let password = [0x01u8; 32];
    let salt = [0x02u8; 16];
    let secret = [0x03u8; 8];
    let ad = [0x04u8; 12];
    let expected = "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8";

    let result = kargon2::derive_with_extras(
        &password,
        &salt,
        &secret,
        &ad,
        kargon2::Config {
            algorithm: kargon2::Algorithm::Argon2i,
            nb_blocks: 32,
            nb_passes: 3,
            nb_lanes: 4,
        },
        32,
    )
    .unwrap();
    assert_eq!(hex(&result), expected);
}

// RFC 9106 §5.3 — Argon2id test vector with associated_data
#[test]
fn argon2id_rfc9106_section_5_3() {
    let password = [0x01u8; 32];
    let salt = [0x02u8; 16];
    let secret = [0x03u8; 8];
    let ad = [0x04u8; 12];
    let expected = "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659";

    let result = kargon2::derive_with_extras(
        &password,
        &salt,
        &secret,
        &ad,
        kargon2::Config {
            algorithm: kargon2::Algorithm::Argon2id,
            nb_blocks: 32,
            nb_passes: 3,
            nb_lanes: 4,
        },
        32,
    )
    .unwrap();
    assert_eq!(hex(&result), expected);
}

// Variable output length: 64-byte derivation produces a different value than
// the first 32 bytes of 32-byte derivation (length is part of the hash domain).
#[test]
fn argon2id_output_length_is_domain_separated() {
    let salt = b"keylock-salt-12345678901234567";
    let cfg = kargon2::Config {
        algorithm: kargon2::Algorithm::Argon2id,
        nb_blocks: 256,
        nb_passes: 1,
        nb_lanes: 1,
    };
    let short = kargon2::derive(b"password", salt, cfg, 32).unwrap();
    let long = kargon2::derive(b"password", salt, cfg, 64).unwrap();
    assert_eq!(short.len(), 32);
    assert_eq!(long.len(), 64);
    assert_ne!(short, long[..32]);
}

// Different pepper produces different output.
#[test]
fn argon2id_pepper_changes_output() {
    let cfg = kargon2::Config {
        algorithm: kargon2::Algorithm::Argon2id,
        nb_blocks: 256,
        nb_passes: 1,
        nb_lanes: 1,
    };
    let salt = b"keylock-salt-12345678";
    let a = kargon2::derive_with_pepper(b"password", salt, b"pepper-a", cfg, 32).unwrap();
    let b = kargon2::derive_with_pepper(b"password", salt, b"pepper-b", cfg, 32).unwrap();
    assert_ne!(a, b);
}

// Invalid params: 0 passes → error.
#[test]
fn argon2_zero_passes_returns_error() {
    let res = kargon2::derive(
        b"pw",
        b"keylock-salt-abcdefgh",
        kargon2::Config {
            algorithm: kargon2::Algorithm::Argon2id,
            nb_blocks: 32,
            nb_passes: 0,
            nb_lanes: 1,
        },
        32,
    );
    assert!(res.is_err());
}
