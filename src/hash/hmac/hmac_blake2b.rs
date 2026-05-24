//! BLAKE2b keyed-MAC compatibility helper.

use blake2::{
    Blake2bMac, Blake2bMac512,
    digest::{FixedOutput, KeyInit, Update, consts::U32},
};

pub const BYTES: usize = 64;
pub const KEYBYTES_MAX: usize = 128;

#[derive(Clone)]
pub struct Context {
    mac: Blake2bMac512,
}

pub fn init(key: &[u8]) -> Context {
    Context {
        mac: Blake2bMac512::new_from_slice(key).expect("BLAKE2b accepts keys up to block size"),
    }
}

pub fn update(ctx: &mut Context, message: &[u8]) {
    ctx.mac.update(message);
}

pub fn final_bytes(ctx: Context) -> Vec<u8> {
    ctx.mac.finalize_fixed().to_vec()
}

pub fn hmac(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut ctx = init(key);
    update(&mut ctx, message);
    final_bytes(ctx)
}

pub fn keyed_32(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac =
        Blake2bMac::<U32>::new_from_slice(key).expect("BLAKE2b accepts keys up to block size");
    mac.update(message);
    mac.finalize_fixed().to_vec()
}
