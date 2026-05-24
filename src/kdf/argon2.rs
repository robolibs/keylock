//! Argon2 KDF compatibility surface.
//!
//! Mirrors `keylock/kdf/argon2/argon2.hpp`, which exposes Argon2d, Argon2i and
//! Argon2id with caller-supplied memory/time/parallelism plus an optional
//! pepper (`key`) and associated_data. The Rust port delegates to the `argon2`
//! crate (RustCrypto) so we get a constant-time, well-reviewed implementation.

use argon2::{Algorithm as ArgonAlgo, Argon2, AssociatedData, ParamsBuilder, Version};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Algorithm {
    Argon2d,
    Argon2i,
    Argon2id,
}

#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub algorithm: Algorithm,
    pub nb_blocks: u32, // memory cost in 1 KiB blocks
    pub nb_passes: u32, // time cost (iterations)
    pub nb_lanes: u32,  // parallelism
}

impl Default for Config {
    fn default() -> Self {
        Self {
            algorithm: Algorithm::Argon2id,
            nb_blocks: 19_456, // ~19 MiB (OWASP minimum)
            nb_passes: 2,
            nb_lanes: 1,
        }
    }
}

pub fn derive(
    password: &[u8],
    salt: &[u8],
    config: Config,
    output_len: usize,
) -> Result<Vec<u8>, String> {
    derive_with_extras(password, salt, &[], &[], config, output_len)
}

pub fn derive_with_pepper(
    password: &[u8],
    salt: &[u8],
    pepper: &[u8],
    config: Config,
    output_len: usize,
) -> Result<Vec<u8>, String> {
    derive_with_extras(password, salt, pepper, &[], config, output_len)
}

pub fn derive_with_extras(
    password: &[u8],
    salt: &[u8],
    pepper: &[u8],
    associated_data: &[u8],
    config: Config,
    output_len: usize,
) -> Result<Vec<u8>, String> {
    let algo = match config.algorithm {
        Algorithm::Argon2d => ArgonAlgo::Argon2d,
        Algorithm::Argon2i => ArgonAlgo::Argon2i,
        Algorithm::Argon2id => ArgonAlgo::Argon2id,
    };

    let mut builder = ParamsBuilder::new();
    builder
        .m_cost(config.nb_blocks)
        .t_cost(config.nb_passes)
        .p_cost(config.nb_lanes)
        .output_len(output_len);
    if !associated_data.is_empty() {
        let ad = AssociatedData::new(associated_data)
            .map_err(|e| format!("Argon2 associated data rejected: {e}"))?;
        builder.data(ad);
    }
    let params = builder
        .build()
        .map_err(|e| format!("Invalid Argon2 parameters: {e}"))?;

    let argon = if pepper.is_empty() {
        Argon2::new(algo, Version::V0x13, params)
    } else {
        Argon2::new_with_secret(pepper, algo, Version::V0x13, params)
            .map_err(|e| format!("Argon2 secret rejected: {e}"))?
    };

    let mut out = vec![0u8; output_len];
    argon
        .hash_password_into(password, salt, &mut out)
        .map_err(|e| format!("Argon2 derivation failed: {e}"))?;
    Ok(out)
}
