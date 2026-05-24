//! SHAKE/cSHAKE extensible-output compatibility helpers.
//!
//! Mirrors `keylock/hash/shake/shake.hpp` and delegates XOF/cSHAKE behavior to
//! the RustCrypto `sha3` crate.

use sha3::{
    CShake128, CShake128Core, CShake256, CShake256Core, Shake128, Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Algorithm {
    Shake128,
    Shake256,
    CShake128,
    CShake256,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Context {
    algorithm: Algorithm,
    function_name: Vec<u8>,
    customization: Vec<u8>,
    data: Vec<u8>,
    squeeze_pos: usize,
}

pub fn init_128() -> Context {
    Context {
        algorithm: Algorithm::Shake128,
        function_name: Vec::new(),
        customization: Vec::new(),
        data: Vec::new(),
        squeeze_pos: 0,
    }
}

pub fn init_256() -> Context {
    Context {
        algorithm: Algorithm::Shake256,
        function_name: Vec::new(),
        customization: Vec::new(),
        data: Vec::new(),
        squeeze_pos: 0,
    }
}

pub fn init_cshake_128(function_name: &[u8], customization: &[u8]) -> Context {
    Context {
        algorithm: Algorithm::CShake128,
        function_name: function_name.to_vec(),
        customization: customization.to_vec(),
        data: Vec::new(),
        squeeze_pos: 0,
    }
}

pub fn init_cshake_256(function_name: &[u8], customization: &[u8]) -> Context {
    Context {
        algorithm: Algorithm::CShake256,
        function_name: function_name.to_vec(),
        customization: customization.to_vec(),
        data: Vec::new(),
        squeeze_pos: 0,
    }
}

pub fn update(ctx: &mut Context, message: &[u8]) {
    ctx.data.extend_from_slice(message);
}

pub fn squeeze(ctx: &mut Context, output_len: usize) -> Vec<u8> {
    let end = ctx.squeeze_pos + output_len;
    let output = match ctx.algorithm {
        Algorithm::Shake128 => shake128(&ctx.data, end),
        Algorithm::Shake256 => shake256(&ctx.data, end),
        Algorithm::CShake128 => cshake128(&ctx.function_name, &ctx.customization, &ctx.data, end),
        Algorithm::CShake256 => cshake256(&ctx.function_name, &ctx.customization, &ctx.data, end),
    };
    let chunk = output[ctx.squeeze_pos..end].to_vec();
    ctx.squeeze_pos = end;
    chunk
}

pub fn final_bytes(ctx: &mut Context) {
    ctx.data.clear();
    ctx.function_name.clear();
    ctx.customization.clear();
    ctx.squeeze_pos = 0;
}

pub fn shake128(message: &[u8], output_len: usize) -> Vec<u8> {
    let mut hasher = Shake128::default();
    hasher.update(message);
    let mut reader = hasher.finalize_xof();
    let mut output = vec![0u8; output_len];
    reader.read(&mut output);
    output
}

pub fn shake256(message: &[u8], output_len: usize) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(message);
    let mut reader = hasher.finalize_xof();
    let mut output = vec![0u8; output_len];
    reader.read(&mut output);
    output
}

pub fn cshake128(
    function_name: &[u8],
    customization: &[u8],
    message: &[u8],
    output_len: usize,
) -> Vec<u8> {
    let mut hasher = CShake128::from_core(CShake128Core::new_with_function_name(
        function_name,
        customization,
    ));
    hasher.update(message);
    let mut output = vec![0u8; output_len];
    hasher.finalize_xof_into(&mut output);
    output
}

pub fn cshake256(
    function_name: &[u8],
    customization: &[u8],
    message: &[u8],
    output_len: usize,
) -> Vec<u8> {
    let mut hasher = CShake256::from_core(CShake256Core::new_with_function_name(
        function_name,
        customization,
    ));
    hasher.update(message);
    let mut output = vec![0u8; output_len];
    hasher.finalize_xof_into(&mut output);
    output
}
