//! Password hashing — the storable form of a secret.
//!
//! [`argon2`](super::argon2) is the raw KDF: give it a password, a salt and
//! cost parameters and it hands back bytes. Storing a password needs more than
//! that — a fresh salt per secret, the parameters recorded so they can be
//! raised later without invalidating what is already stored, and a
//! constant-time comparison. Assembling those correctly is exactly the sort of
//! thing every caller should *not* be reinventing.
//!
//! So this is the construct: [`hash`] produces one self-describing string and
//! [`verify`] checks a password against it. Mirrors libsodium's
//! `crypto_pwhash_str` / `crypto_pwhash_str_verify` pair.
//!
//! The encoding is the standard PHC string format, so a stored hash is
//! portable and readable:
//!
//! ```text
//! $argon2id$v=19$m=19456,t=2,p=1$<base64 salt>$<base64 digest>
//! ```
//!
//! Because the parameters travel inside the string, raising the cost affects
//! only newly stored secrets; existing ones keep verifying under the
//! parameters they were made with.

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm as ArgonAlgo, Argon2, ParamsBuilder, Version};

pub use super::argon2::{Algorithm, Config};

fn hasher(config: Config) -> Result<Argon2<'static>, String> {
    let algo = match config.algorithm {
        Algorithm::Argon2d => ArgonAlgo::Argon2d,
        Algorithm::Argon2i => ArgonAlgo::Argon2i,
        Algorithm::Argon2id => ArgonAlgo::Argon2id,
    };
    let mut builder = ParamsBuilder::new();
    builder
        .m_cost(config.nb_blocks)
        .t_cost(config.nb_passes)
        .p_cost(config.nb_lanes);
    let params = builder.build().map_err(|e| e.to_string())?;
    Ok(Argon2::new(algo, Version::V0x13, params))
}

/// Hash `password` for storage under the default cost ([`Config::default`],
/// the OWASP minimum), with a fresh random salt.
pub fn hash(password: &[u8]) -> Result<String, String> {
    hash_with(password, Config::default())
}

/// As [`hash`], with explicit cost parameters.
///
/// Lowering these makes verification faster and an offline attack on a stolen
/// store cheaper in exactly the same proportion. Only do it where that trade
/// is deliberate — a test suite, say.
pub fn hash_with(password: &[u8], config: Config) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    hasher(config)?
        .hash_password(password, &salt)
        .map(|hash| hash.to_string())
        .map_err(|e| e.to_string())
}

/// Whether `password` matches the stored PHC string.
///
/// Cost parameters are read from `stored`, so a hash made under older, cheaper
/// settings still verifies. Comparison is constant-time. A malformed `stored`
/// is a `false`, never a panic.
pub fn verify(stored: &str, password: &[u8]) -> bool {
    let Ok(parsed) = PasswordHash::new(stored) else {
        return false;
    };
    // Any Argon2 variant/parameters are taken from the parsed hash itself.
    Argon2::default().verify_password(password, &parsed).is_ok()
}

/// The cost parameters a stored hash was made with, if it parses.
///
/// Lets a caller notice a secret stored under weaker settings than it now
/// requires, and re-hash it the next time the password is presented.
pub fn stored_cost(stored: &str) -> Option<Config> {
    let parsed = PasswordHash::new(stored).ok()?;
    let params = argon2::Params::try_from(&parsed).ok()?;
    let algorithm = match parsed.algorithm.as_str() {
        "argon2d" => Algorithm::Argon2d,
        "argon2i" => Algorithm::Argon2i,
        _ => Algorithm::Argon2id,
    };
    Some(Config {
        algorithm,
        nb_blocks: params.m_cost(),
        nb_passes: params.t_cost(),
        nb_lanes: params.p_cost(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cheap() -> Config {
        Config {
            algorithm: Algorithm::Argon2id,
            nb_blocks: 8,
            nb_passes: 1,
            nb_lanes: 1,
        }
    }

    #[test]
    fn round_trips() {
        let stored = hash_with(b"correct horse", cheap()).expect("hash");
        assert!(verify(&stored, b"correct horse"));
        assert!(!verify(&stored, b"correct hors"));
        assert!(!verify(&stored, b""));
    }

    #[test]
    fn is_a_phc_string() {
        let stored = hash_with(b"s3cret", cheap()).expect("hash");
        assert!(stored.starts_with("$argon2id$"), "got {stored}");
        assert!(stored.contains("m=8,t=1,p=1"), "got {stored}");
    }

    /// The salt is per secret, so two identical passwords must not produce
    /// identical stored forms — otherwise one cracked pairing breaks both.
    #[test]
    fn identical_passwords_hash_differently() {
        let a = hash_with(b"same", cheap()).expect("hash");
        let b = hash_with(b"same", cheap()).expect("hash");
        assert_ne!(a, b);
        assert!(verify(&a, b"same") && verify(&b, b"same"));
    }

    /// Parameters live in the stored string, so raising the cost later does
    /// not invalidate what is already stored.
    #[test]
    fn old_hashes_verify_after_a_cost_increase() {
        let stored = hash_with(b"legacy", cheap()).expect("hash");
        assert_eq!(stored_cost(&stored).expect("cost").nb_blocks, 8);
        // A caller that has since raised its own default still verifies this.
        assert!(verify(&stored, b"legacy"));
    }

    #[test]
    fn garbage_is_false_not_a_panic() {
        for junk in ["", "not a hash", "$argon2id$", "$argon2id$v=19$m=8$bad$bad"] {
            assert!(!verify(junk, b"anything"), "{junk:?} verified");
            assert!(stored_cost(junk).is_none() || !junk.is_empty());
        }
    }
}
