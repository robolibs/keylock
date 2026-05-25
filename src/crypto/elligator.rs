//! Elligator2 mapping for Curve25519.
//!
//! Mirrors `keylock/crypto/elligator/elligator2.hpp` (itself adapted from
//! Monocypher / Loup Vaillant). Lets X25519 public keys be encoded as
//! random-looking 32-byte strings for censorship-resistant protocols.
//!
//! The C++ reference implements the field arithmetic in radix 2^25.5 (the
//! Monocypher/TweetNaCl format). Since `curve25519-dalek` does not expose its
//! `FieldElement` type, we instead do the math in `num-bigint`. The non-square
//! is `2`, matching the C++ port.
//!
//! Note: this implementation is **not constant-time**. Elligator2 use cases
//! (representing public keys; the C++ port flagged the same limitation) tolerate
//! non-constant-time arithmetic since the inputs/outputs are public.

use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::{One, Zero};

fn prime() -> BigUint {
    // 2^255 - 19
    (BigUint::one() << 255u32) - BigUint::from(19u32)
}

fn a_coeff() -> BigUint {
    BigUint::from(486_662u32)
}

fn non_square() -> BigUint {
    BigUint::from(2u32)
}

fn modp(value: BigUint) -> BigUint {
    value.mod_floor(&prime())
}

fn neg(value: &BigUint) -> BigUint {
    let p = prime();
    if value.is_zero() {
        BigUint::zero()
    } else {
        (&p - value).mod_floor(&p)
    }
}

fn mul(a: &BigUint, b: &BigUint) -> BigUint {
    modp(a * b)
}

fn sq(a: &BigUint) -> BigUint {
    mul(a, a)
}

fn add(a: &BigUint, b: &BigUint) -> BigUint {
    modp(a + b)
}

fn inv(a: &BigUint) -> BigUint {
    // a^(p-2) mod p
    let p = prime();
    a.modpow(&(&p - BigUint::from(2u32)), &p)
}

// (p - 1) / 2 — used for Legendre symbol.
fn p_minus_one_over_two() -> BigUint {
    (prime() - BigUint::one()) >> 1
}

fn legendre(a: &BigUint) -> i32 {
    if a.is_zero() {
        return 0;
    }
    let result = a.modpow(&p_minus_one_over_two(), &prime());
    if result.is_one() { 1 } else { -1 }
}

// sqrt(a) for p ≡ 5 (mod 8) using the Atkin shortcut, where a is known to be a
// QR. Returns the principal root.
fn sqrt(a: &BigUint) -> BigUint {
    let p = prime();
    // For p = 2^255 - 19, p ≡ 5 (mod 8), so we use:
    //   if a^((p-1)/4) = 1: x = a^((p+3)/8)
    //   else:               x = a^((p+3)/8) * sqrt(-1)
    // sqrt(-1) mod p = 2^((p-1)/4)
    let exp_a = (&p + BigUint::from(3u32)) >> 3;
    let mut x = a.modpow(&exp_a, &p);
    let check = mul(&x, &x);
    if check != *a {
        let sqrt_m1 = BigUint::from(2u32).modpow(&((&p - BigUint::one()) >> 2), &p);
        x = mul(&x, &sqrt_m1);
    }
    x
}

/// For forward map: mask top 2 bits (`r < 2^254`).
fn decode_repr(bytes: &[u8; 32]) -> BigUint {
    let mut masked = *bytes;
    masked[31] &= 0x3f;
    BigUint::from_bytes_le(&masked)
}

/// For reverse map input: mask only bit 255 (`u < 2^255`).
fn decode_pubkey(bytes: &[u8; 32]) -> BigUint {
    let mut masked = *bytes;
    masked[31] &= 0x7f;
    BigUint::from_bytes_le(&masked)
}

fn encode_le_32(value: &BigUint) -> [u8; 32] {
    let mut bytes = value.to_bytes_le();
    bytes.resize(32, 0);
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes[..32]);
    out
}

/// Map a 32-byte representative (hidden) to a Curve25519 u-coordinate.
pub fn map(hidden: &[u8; 32]) -> [u8; 32] {
    let r = decode_repr(hidden);
    let a = a_coeff();
    let ns = non_square();
    // v = -A / (1 + non_square * r^2)
    let denom = add(&BigUint::one(), &mul(&ns, &sq(&r)));
    let v = mul(&neg(&a), &inv(&denom));
    // gnu = v^3 + A*v^2 + v
    let v_sq = sq(&v);
    let gnu = add(&add(&mul(&v_sq, &v), &mul(&a, &v_sq)), &v);
    let u = if legendre(&gnu) == 1 {
        v
    } else {
        neg(&add(&v, &a))
    };
    encode_le_32(&u)
}

/// Compute the representative of a Curve25519 public key, if one exists.
///
/// Returns `Some(hidden)` on success. The lower 254 bits are set deterministically
/// from `public_key`; the top 2 bits come from `tweak` for randomness padding.
/// Returns `None` if the point has no Elligator2 representative (about half of
/// all valid u-coordinates).
pub fn reverse(public_key: &[u8; 32], tweak: u8) -> Option<[u8; 32]> {
    let u = decode_pubkey(public_key);
    let a = a_coeff();
    let ns = non_square();
    // We need to find r such that map(r) = u. The original Monocypher logic
    // (`t3 = sqrt(-1 / (non_square * u * (u + A)))`, branch on is_square, then
    // multiply by u or u+A) corresponds to the algebra below.
    let u_plus_a = add(&u, &a);
    if u_plus_a.is_zero() || u.is_zero() {
        return None;
    }
    // Squareness check is on -u*(u+A)/Z (equivalent for both branches).
    let test = mul(&neg(&mul(&u, &u_plus_a)), &inv(&ns));
    if legendre(&test) != 1 {
        return None;
    }
    // Pick the branch indicated by the tweak bit.
    let candidate = if (tweak & 1) == 0 {
        // r^2 = -u / (Z*(u+A))
        mul(&neg(&u), &inv(&mul(&ns, &u_plus_a)))
    } else {
        // r^2 = -(u+A) / (Z*u)
        mul(&neg(&u_plus_a), &inv(&mul(&ns, &u)))
    };
    // Two roots: r and p-r. Forward map's decoder masks the top 2 bits, so
    // we need a root with value < 2^254 so masking is a no-op. Exactly one of
    // {root, p-root} satisfies that.
    let root = sqrt(&candidate);
    let alt = neg(&root);
    let threshold = BigUint::one() << 254u32;
    let r = if root < threshold { root } else { alt };

    let mut out = encode_le_32(&r);
    // Pad upper 2 bits with random tweak bits to fill the 256-bit string.
    out[31] |= tweak & 0xc0;
    Some(out)
}
