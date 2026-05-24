//! KMAC128/KMAC256 compatibility helpers.
//!
//! The C++ source carries a local Keccak permutation for KMAC.  The Rust port
//! keeps the same `keylock::hash::kmac` module boundary, but delegates the
//! cSHAKE primitive to the RustCrypto `sha3` crate and only applies the
//! SP800-185 KMAC framing around it.

use sha3::{
    CShake128, CShake128Core, CShake128Reader, CShake256, CShake256Core, CShake256Reader,
    digest::{ExtendableOutput, Update, XofReader},
};

enum Hasher {
    Kmac128(CShake128),
    Kmac256(CShake256),
}

enum Reader {
    Kmac128(CShake128Reader),
    Kmac256(CShake256Reader),
}

pub struct Context {
    hasher: Option<Hasher>,
    reader: Option<Reader>,
    output_size: usize,
    is_xof: bool,
}

fn left_encode(num: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut value = num;
    bytes.push((value & 0xff) as u8);
    value >>= 8;
    while value != 0 {
        bytes.push((value & 0xff) as u8);
        value >>= 8;
    }
    bytes.reverse();

    let mut out = Vec::with_capacity(bytes.len() + 1);
    out.push(bytes.len() as u8);
    out.extend(bytes);
    out
}

fn right_encode(num: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut value = num;
    bytes.push((value & 0xff) as u8);
    value >>= 8;
    while value != 0 {
        bytes.push((value & 0xff) as u8);
        value >>= 8;
    }
    bytes.reverse();
    bytes.push(bytes.len() as u8);
    bytes
}

fn encode_string(data: &[u8]) -> Vec<u8> {
    let mut out = left_encode(data.len() * 8);
    out.extend_from_slice(data);
    out
}

fn bytepad(encoded: &[u8], rate: usize) -> Vec<u8> {
    let mut out = left_encode(rate);
    out.extend_from_slice(encoded);
    let pad_len = (rate - (out.len() % rate)) % rate;
    out.resize(out.len() + pad_len, 0);
    out
}

pub fn init_128(key: &[u8], customization: &[u8], output_size: usize) -> Context {
    let mut hasher = CShake128::from_core(CShake128Core::new_with_function_name(
        b"KMAC",
        customization,
    ));
    hasher.update(&bytepad(&encode_string(key), 168));
    Context {
        hasher: Some(Hasher::Kmac128(hasher)),
        reader: None,
        output_size,
        is_xof: output_size == 0,
    }
}

pub fn init_256(key: &[u8], customization: &[u8], output_size: usize) -> Context {
    let mut hasher = CShake256::from_core(CShake256Core::new_with_function_name(
        b"KMAC",
        customization,
    ));
    hasher.update(&bytepad(&encode_string(key), 136));
    Context {
        hasher: Some(Hasher::Kmac256(hasher)),
        reader: None,
        output_size,
        is_xof: output_size == 0,
    }
}

pub fn update(ctx: &mut Context, message: &[u8]) {
    match ctx.hasher.as_mut() {
        Some(Hasher::Kmac128(hasher)) => hasher.update(message),
        Some(Hasher::Kmac256(hasher)) => hasher.update(message),
        None => panic!("cannot update KMAC context after squeezing"),
    }
}

pub fn squeeze(ctx: &mut Context, output_size: usize) -> Vec<u8> {
    if ctx.reader.is_none() {
        let encoded_len = if ctx.is_xof {
            right_encode(0)
        } else {
            right_encode(ctx.output_size * 8)
        };

        let hasher = ctx
            .hasher
            .take()
            .expect("KMAC context must contain a hasher before squeezing");
        ctx.reader = Some(match hasher {
            Hasher::Kmac128(mut hasher) => {
                hasher.update(&encoded_len);
                Reader::Kmac128(hasher.finalize_xof())
            }
            Hasher::Kmac256(mut hasher) => {
                hasher.update(&encoded_len);
                Reader::Kmac256(hasher.finalize_xof())
            }
        });
    }

    let mut out = vec![0u8; output_size];
    match ctx.reader.as_mut().expect("reader initialized") {
        Reader::Kmac128(reader) => reader.read(&mut out),
        Reader::Kmac256(reader) => reader.read(&mut out),
    }
    out
}

pub fn final_bytes(ctx: &mut Context) -> Vec<u8> {
    squeeze(ctx, ctx.output_size)
}

pub fn final_xof(_ctx: Context) {}

pub fn kmac128(key: &[u8], customization: &[u8], message: &[u8], output_size: usize) -> Vec<u8> {
    let mut ctx = init_128(key, customization, output_size);
    update(&mut ctx, message);
    squeeze(&mut ctx, output_size)
}

pub fn kmac256(key: &[u8], customization: &[u8], message: &[u8], output_size: usize) -> Vec<u8> {
    let mut ctx = init_256(key, customization, output_size);
    update(&mut ctx, message);
    squeeze(&mut ctx, output_size)
}
