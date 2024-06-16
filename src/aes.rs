use aes_gcm::{aead::{Aead, OsRng}, AeadCore, Aes256Gcm, KeyInit};

const CONTENT_KEY: [u8; 32] = [
    0x50, 0x1b, 0x9f, 0x4e, 0xa5, 0xa0, 0x30, 0x1f,
    0x2d, 0x7b, 0xa7, 0x3d, 0xf2, 0xe4, 0x0f, 0x80,
    0x1c, 0xaa, 0x27, 0xb5, 0x65, 0x0f, 0x9d, 0xa7,
    0x10, 0x7a, 0x8c, 0xa9, 0xaf, 0x62, 0x84, 0xb6,
];

const HEADER_KEY: [u8; 32] = [
    0x63, 0x2a, 0x64, 0x08, 0x49, 0xee, 0xef, 0x23,
    0x29, 0x3d, 0xd9, 0x3a, 0x62, 0xd0, 0xb6, 0x17,
    0xf2, 0xb5, 0x30, 0x00, 0x81, 0xce, 0x3b, 0x63,
    0x9e, 0xaa, 0xd4, 0xc4, 0xc1, 0xc7, 0xaa, 0xe2,
];

pub enum Keys {
    Content,
    Header,
}

pub struct AES {
    cipher: Aes256Gcm,
}

impl AES {
    pub fn new(key: Keys) -> Self {
        let key = match key {
            Keys::Content => CONTENT_KEY,
            Keys::Header => HEADER_KEY,
        };

        Self {
            cipher: Aes256Gcm::new(&key.into())
        }
    }

    pub fn encrypt_ctr(&self, data: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        (self.cipher.encrypt(&nonce, data.as_ref()).unwrap(), nonce.to_vec())
    }

    #[allow(dead_code)]
    pub fn decrypt_ctr(&self, data: &[u8], nonce: &[u8]) -> Vec<u8> {
        self.cipher.decrypt(nonce.into(), data.as_ref()).unwrap()
    }
}