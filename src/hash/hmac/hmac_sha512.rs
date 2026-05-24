//! HMAC-SHA512 compatibility helper.

use hmac::{Hmac, Mac};
use sha2::Sha512;

pub const BYTES: usize = 64;
pub const KEYBYTES_MAX: usize = 128;

type HmacSha512 = Hmac<Sha512>;

#[derive(Clone)]
pub struct Context {
    mac: HmacSha512,
}

pub fn init(key: &[u8]) -> Context {
    Context {
        mac: HmacSha512::new_from_slice(key).expect("HMAC accepts any key length"),
    }
}

pub fn update(ctx: &mut Context, message: &[u8]) {
    ctx.mac.update(message);
}

pub fn final_bytes(ctx: Context) -> Vec<u8> {
    ctx.mac.finalize().into_bytes().to_vec()
}

pub fn hmac(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut ctx = init(key);
    update(&mut ctx, message);
    final_bytes(ctx)
}
