//! Encryption for tests only: the production binary never encrypts.
use super::*;
use cbc::cipher::BlockModeEncrypt;

pub fn encrypt2(key: &SymKey, iv: [u8; 16], plain: &[u8]) -> String {
    let mut ct = plain.to_vec();
    ct.resize(plain.len() + AES_BLOCK, 0);
    let len = cbc::Encryptor::<Aes256>::new(&(*key.enc).into(), &iv.into())
        .encrypt_padded::<Pkcs7>(&mut ct, plain.len())
        .unwrap()
        .len();
    ct.truncate(len);
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&*key.mac).unwrap();
    mac.update(&iv);
    mac.update(&ct);
    let mac = mac.finalize().into_bytes();
    format!(
        "2.{}|{}|{}",
        STANDARD.encode(iv),
        STANDARD.encode(ct),
        STANDARD.encode(mac)
    )
}

pub fn key(seed: u8) -> SymKey {
    let bytes: Vec<u8> = (0..64u8)
        .map(|i| i.wrapping_mul(7).wrapping_add(seed))
        .collect();
    SymKey::from_slice(&bytes).unwrap()
}
