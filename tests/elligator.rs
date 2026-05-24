use keylock::crypto::elligator;
use x25519_dalek::{PublicKey, StaticSecret};

fn rand_bytes(out: &mut [u8]) {
    getrandom::getrandom(out).expect("rng");
}

#[test]
fn elligator2_forward_map_produces_valid_x25519_point() {
    // A random 32-byte representative always maps to *some* u-coordinate.
    let mut hidden = [0u8; 32];
    rand_bytes(&mut hidden);
    let u = elligator::map(&hidden);
    // The result is a valid u-coordinate that we can do scalarmult against.
    let mut sk = [0u8; 32];
    rand_bytes(&mut sk);
    let secret = StaticSecret::from(sk);
    let pubpoint = PublicKey::from(u);
    let _shared = secret.diffie_hellman(&pubpoint);
}

#[test]
fn elligator2_reverse_then_forward_recovers_public_key_when_representable() {
    // Try a handful of random X25519 public keys. Roughly half are representable.
    let mut attempts = 0;
    let mut successes = 0;
    while successes < 5 && attempts < 200 {
        attempts += 1;
        let mut sk = [0u8; 32];
        rand_bytes(&mut sk);
        let secret = StaticSecret::from(sk);
        let public_bytes = *PublicKey::from(&secret).as_bytes();

        let mut tweak = [0u8; 1];
        rand_bytes(&mut tweak);
        if let Some(hidden) = elligator::reverse(&public_bytes, tweak[0]) {
            let recovered = elligator::map(&hidden);
            assert_eq!(
                recovered, public_bytes,
                "Elligator2 reverse → map round-trip mismatch"
            );
            successes += 1;
        }
    }
    assert!(
        successes >= 5,
        "expected at least 5 representable points out of {attempts} tries (got {successes})"
    );
}
