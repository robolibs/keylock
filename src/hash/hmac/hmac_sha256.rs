//! HMAC-SHA256 compatibility helper.

use hmac::{Hmac, Mac};
use sha2::Sha256;

pub const BYTES: usize = 32;
pub const KEYBYTES_MAX: usize = 64;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
pub struct Context {
    mac: HmacSha256,
}

pub fn init(key: &[u8]) -> Context {
    Context {
        mac: HmacSha256::new_from_slice(key).expect("HMAC accepts any key length"),
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
