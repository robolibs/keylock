//! HMAC-SHA384 compatibility helper.

use hmac::{Hmac, Mac};
use sha2::Sha384;

pub const BYTES: usize = 48;
pub const KEYBYTES_MAX: usize = 128;

type HmacSha384 = Hmac<Sha384>;

#[derive(Clone)]
pub struct Context {
    mac: HmacSha384,
}

pub fn init(key: &[u8]) -> Context {
    Context {
        mac: HmacSha384::new_from_slice(key).expect("HMAC accepts any key length"),
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
