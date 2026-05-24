//! AES block/CTR/CBC compatibility helper.
//!
//! The C++ source keeps this at `keylock/crypto/aes/aes.hpp` and implements
//! AES plus CTR/CBC locally.  The Rust port keeps the same keylock crypto
//! boundary but delegates the block cipher to the RustCrypto `aes` crate and
//! keeps the small mode glue needed by the C++ test surface.

use ::aes::{
    Aes128, Aes192, Aes256,
    cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray},
};

pub const BLOCK_SIZE: usize = 16;
pub const KEY_SIZE_128: usize = 16;
pub const KEY_SIZE_192: usize = 24;
pub const KEY_SIZE_256: usize = 32;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Context {
    key: Vec<u8>,
}

pub fn init(key: &[u8]) -> Context {
    let mut ctx = Context::default();
    init_context(&mut ctx, key);
    ctx
}

pub fn init_context(ctx: &mut Context, key: &[u8]) -> bool {
    if !matches!(key.len(), KEY_SIZE_128 | KEY_SIZE_192 | KEY_SIZE_256) {
        ctx.key.clear();
        return false;
    }
    ctx.key.clear();
    ctx.key.extend_from_slice(key);
    true
}

pub fn is_initialized(ctx: &Context) -> bool {
    matches!(ctx.key.len(), KEY_SIZE_128 | KEY_SIZE_192 | KEY_SIZE_256)
}

pub fn encrypt_block(ctx: &Context, input: &[u8]) -> Vec<u8> {
    crypt_block(ctx, input, true)
}

pub fn decrypt_block(ctx: &Context, input: &[u8]) -> Vec<u8> {
    crypt_block(ctx, input, false)
}

pub fn encrypt_block_into(ctx: &Context, input: &[u8], output: &mut [u8]) -> bool {
    let block = encrypt_block(ctx, input);
    if block.len() != BLOCK_SIZE || output.len() < BLOCK_SIZE {
        return false;
    }
    output[..BLOCK_SIZE].copy_from_slice(&block);
    true
}

pub fn decrypt_block_into(ctx: &Context, input: &[u8], output: &mut [u8]) -> bool {
    let block = decrypt_block(ctx, input);
    if block.len() != BLOCK_SIZE || output.len() < BLOCK_SIZE {
        return false;
    }
    output[..BLOCK_SIZE].copy_from_slice(&block);
    true
}

pub fn ctr_crypt(ctx: &Context, nonce: &[u8], input: &[u8]) -> Vec<u8> {
    if !is_initialized(ctx) || nonce.len() != BLOCK_SIZE {
        return Vec::new();
    }
    let mut counter = [0u8; BLOCK_SIZE];
    counter.copy_from_slice(nonce);
    let mut out = vec![0u8; input.len()];
    for (chunk_in, chunk_out) in input.chunks(BLOCK_SIZE).zip(out.chunks_mut(BLOCK_SIZE)) {
        let keystream = encrypt_block(ctx, &counter);
        for (dst, (src, key_byte)) in chunk_out.iter_mut().zip(chunk_in.iter().zip(keystream)) {
            *dst = *src ^ key_byte;
        }
        incr_counter(&mut counter);
    }
    out
}

pub fn cbc_encrypt(ctx: &Context, iv: &[u8], input: &[u8]) -> Vec<u8> {
    if !is_initialized(ctx) || iv.len() != BLOCK_SIZE {
        return Vec::new();
    }
    let mut prev = [0u8; BLOCK_SIZE];
    prev.copy_from_slice(iv);
    let mut out = vec![0u8; input.len()];
    for (chunk_in, chunk_out) in input
        .chunks_exact(BLOCK_SIZE)
        .zip(out.chunks_exact_mut(BLOCK_SIZE))
    {
        let mut block = [0u8; BLOCK_SIZE];
        for idx in 0..BLOCK_SIZE {
            block[idx] = chunk_in[idx] ^ prev[idx];
        }
        let encrypted = encrypt_block(ctx, &block);
        chunk_out.copy_from_slice(&encrypted);
        prev.copy_from_slice(&encrypted);
    }
    out
}

pub fn cbc_decrypt(ctx: &Context, iv: &[u8], input: &[u8]) -> Vec<u8> {
    if !is_initialized(ctx) || iv.len() != BLOCK_SIZE {
        return Vec::new();
    }
    let mut prev = [0u8; BLOCK_SIZE];
    prev.copy_from_slice(iv);
    let mut out = vec![0u8; input.len()];
    for (chunk_in, chunk_out) in input
        .chunks_exact(BLOCK_SIZE)
        .zip(out.chunks_exact_mut(BLOCK_SIZE))
    {
        let decrypted = decrypt_block(ctx, chunk_in);
        for idx in 0..BLOCK_SIZE {
            chunk_out[idx] = decrypted[idx] ^ prev[idx];
        }
        prev.copy_from_slice(chunk_in);
    }
    out
}

fn crypt_block(ctx: &Context, input: &[u8], encrypt: bool) -> Vec<u8> {
    if input.len() != BLOCK_SIZE {
        return Vec::new();
    }
    let mut block = GenericArray::clone_from_slice(input);
    match ctx.key.len() {
        KEY_SIZE_128 => {
            let cipher = Aes128::new(GenericArray::from_slice(&ctx.key));
            if encrypt {
                cipher.encrypt_block(&mut block);
            } else {
                cipher.decrypt_block(&mut block);
            }
        }
        KEY_SIZE_192 => {
            let cipher = Aes192::new(GenericArray::from_slice(&ctx.key));
            if encrypt {
                cipher.encrypt_block(&mut block);
            } else {
                cipher.decrypt_block(&mut block);
            }
        }
        KEY_SIZE_256 => {
            let cipher = Aes256::new(GenericArray::from_slice(&ctx.key));
            if encrypt {
                cipher.encrypt_block(&mut block);
            } else {
                cipher.decrypt_block(&mut block);
            }
        }
        _ => return Vec::new(),
    }
    block.to_vec()
}

fn incr_counter(counter: &mut [u8; BLOCK_SIZE]) {
    for byte in counter.iter_mut().rev() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            break;
        }
    }
}
