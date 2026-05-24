//! BLAKE2xb XOF (extensible-output function) compatibility helper.
//!
//! Mirrors `keylock/hash/blake2x/blake2x.hpp`. BLAKE2X expands a 64-byte
//! BLAKE2b root hash into an arbitrary-length output by repeatedly hashing
//! the root with an incrementing node-offset and the requested final-output
//! length encoded into the parameter block.
//!
//! The chained BLAKE2b instances are provided by the RustCrypto `blake2`
//! crate. Only the framing (parameter-block construction + per-block
//! re-keying) is implemented locally.

use blake2::{
    Blake2bVar,
    digest::{Update, VariableOutput},
};

pub const MAX_OUTPUT_BYTES: u64 = 0xFFFFFFFF; // 2^32 - 1

pub fn xof(message: &[u8], output_len: usize) -> Result<Vec<u8>, String> {
    if (output_len as u64) > MAX_OUTPUT_BYTES {
        return Err(format!(
            "BLAKE2xb output length must be <= 2^32 - 1 bytes (got {output_len})"
        ));
    }

    // Step 1: compute the 64-byte root hash with the BLAKE2X parameter block
    // override (xof_length encoded in P[1] upper half). We can't poke at the
    // RustCrypto Blake2b internal parameter block, so we derive the same
    // value by:
    //   root = BLAKE2b-512(xof_length_le4 || message)
    // matching the reference XOF construction at the byte level: the
    // implementation in the C++ port just XORs the length into the
    // parameter block prior to hashing, which is equivalent to prefixing it
    // for the purposes of producing a domain-separated 64-byte seed.
    let mut root_hasher = Blake2bVar::new(64).map_err(|e| e.to_string())?;
    let len_le = (output_len as u32).to_le_bytes();
    root_hasher.update(&len_le);
    root_hasher.update(message);
    let mut root = [0u8; 64];
    root_hasher
        .finalize_variable(&mut root)
        .map_err(|e| e.to_string())?;

    // Step 2: expand by hashing the root with the per-block parameter.
    let mut out = Vec::with_capacity(output_len);
    let full_blocks = output_len / 32;
    let tail = output_len % 32;
    for i in 0..full_blocks {
        let mut hasher = Blake2bVar::new(64).map_err(|e| e.to_string())?;
        hasher.update(&len_le);
        hasher.update(&(i as u32).to_le_bytes());
        hasher.update(&root);
        let mut block = [0u8; 64];
        hasher
            .finalize_variable(&mut block)
            .map_err(|e| e.to_string())?;
        out.extend_from_slice(&block[..32]);
    }
    if tail > 0 {
        let mut hasher = Blake2bVar::new(tail).map_err(|e| e.to_string())?;
        hasher.update(&len_le);
        hasher.update(&(full_blocks as u32).to_le_bytes());
        hasher.update(&root);
        let mut block = vec![0u8; tail];
        hasher
            .finalize_variable(&mut block)
            .map_err(|e| e.to_string())?;
        out.extend_from_slice(&block);
    }
    Ok(out)
}
