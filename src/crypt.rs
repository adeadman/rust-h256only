use crypto::hmac::Hmac;
use crypto::mac::{
    Mac,
    MacResult,
};
use crypto::sha2::Sha256;
use rustc_serialize::base64::{
    FromBase64,
    ToBase64,
};
use BASE_CONFIG;

pub fn sign(data: &str, key: &[u8]) -> String {
    let mut hmac = Hmac::new(Sha256::new(), key);
    hmac.input(data.as_bytes());

    let mac = hmac.result();
    let code = mac.code();
    (*code).to_base64(BASE_CONFIG)
}

pub fn verify(target: &str, data: &str, key: &[u8]) -> bool {
    let target_bytes = match target.from_base64() {
        Ok(x) => x,
        Err(_) => return false,
    };
    let target_mac = MacResult::new_from_owned(target_bytes);

    let mut hmac = Hmac::new(Sha256::new(), key);
    hmac.input(data.as_bytes());

    hmac.result() == target_mac
}
