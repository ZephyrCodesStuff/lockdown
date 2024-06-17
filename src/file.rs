use std::{fs::File, io::Read, path::PathBuf};

use crate::{aes::{Keys, AES}, Magic};

// b"LOCKDOWN" as u64
pub const MAGIC: &[u8; 8] = b"LOCKDOWN";
pub const MAGIC_NUMBERS: [u64; 8] = [
    0x7DB89D51EE5610B8,
    0xB548CC18F4F23044,
    0xC6F016239C36A278,
    0xF937DFBA56986CF4,
    0xD59AB31623E0AF72,
    0x5CECAC3E1F4944D7,
    0xD49623671F2E468D,
    0xCF04B8ECA23CDB6C
];

#[repr(u8)]
#[derive(Debug, Copy, Clone)]
pub enum Algorithm {
    AES256GCM
}

impl Algorithm {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        match bytes[0] {
            0 => Self::AES256GCM,
            _ => panic!("Invalid algorithm")
        }
    }
}

#[allow(dead_code)]
pub struct EncryptedFile {
    pub magic: Magic,
    pub nonce: Vec<u8>,

    pub header: Header,
    pub header_plaintext: Vec<u8>,
    pub header_ciphertext: Vec<u8>,

    pub plaintext: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

pub struct Header {
    pub path_length: u8,
    pub path: String,

    pub nonce: Vec<u8>,

    pub algorithm: Algorithm,
}

impl EncryptedFile {
    pub fn is_encrypted(path: &PathBuf) -> bool {
        let mut file = File::open(path).unwrap();
        let mut magic = [0; 8];
        file.read_exact(&mut magic).unwrap();

        if &magic == MAGIC {
            true
        } else if MAGIC_NUMBERS.iter().any(|&m| m.to_le_bytes() == magic) {
            true
        } else {
            false
        }
    }

    pub fn new(path: PathBuf, magic: Magic) -> Self {
        let mut plaintext = Vec::new();
        let mut file = File::open(path.clone()).unwrap();
        file.read_to_end(&mut plaintext).unwrap();

        // Encrypt the file
        let aes = AES::new(Keys::Content);
        let (ciphertext, nonce) = aes.encrypt_ctr(&mut plaintext);

        let path_str = path.to_str().unwrap();

        let header = Header {
            path_length: path_str.len() as u8,
            path: path_str.to_string(),

            nonce,

            algorithm: Algorithm::AES256GCM,
        };

        // Encrypt the header
        let header_bytes = header.to_bytes();
        let aes = AES::new(Keys::Header);
        let (encrypted_header, nonce) = aes.encrypt_ctr(&header_bytes);

        Self {
            magic,
            nonce,
            
            header,
            header_plaintext: header_bytes,
            header_ciphertext: encrypted_header,

            plaintext,
            ciphertext
        }
    }
}

impl EncryptedFile {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Write the magic string
        bytes.extend_from_slice(&self.magic.to_bytes());

        // Write the nonce
        bytes.push(self.nonce.len() as u8);
        bytes.extend_from_slice(&self.nonce);

        // Write the header
        bytes.push(self.header_ciphertext.len() as u8);
        bytes.extend_from_slice(&self.header_ciphertext);

        // Write the ciphertext
        bytes.push(self.ciphertext.len() as u8);
        bytes.extend_from_slice(&self.ciphertext);

        bytes
    }

    #[allow(dead_code)]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut offset = 0;

        // Read the magic string
        let mut magic = [0; 8];
        magic.copy_from_slice(&bytes[offset..offset + 8]);
        offset += 8;

        let magic = Magic::from_bytes(&magic).expect("Invalid magic");

        // Read the nonce
        let nonce_length = bytes[offset];
        offset += 1;

        let mut nonce = Vec::new();
        nonce.extend_from_slice(&bytes[offset..offset + nonce_length as usize]);
        offset += nonce_length as usize;

        // Read the header
        let header_length = bytes[offset];
        offset += 1;

        let mut header_ciphertext = Vec::new();
        header_ciphertext.extend_from_slice(&bytes[offset..offset + header_length as usize]);
        offset += header_length as usize;

        // Read the ciphertext
        let ciphertext_length = bytes[offset];
        offset += 1;

        let mut ciphertext = Vec::new();
        ciphertext.extend_from_slice(&bytes[offset..offset + ciphertext_length as usize]);

        // Decrypt the header
        let aes = AES::new(Keys::Header);
        let header_bytes = aes.decrypt_ctr(&header_ciphertext, &nonce);

        // Parse the header
        let header = Header::from_bytes(&header_bytes);

        // Decrypt the ciphertext
        let aes = AES::new(Keys::Content);
        let plaintext = aes.decrypt_ctr(&ciphertext, &header.nonce);

        Self {
            magic,
            nonce,

            header,
            header_plaintext: header_bytes,
            header_ciphertext,

            plaintext,
            ciphertext
        }
    }
}

impl Header {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Write the path
        bytes.push(self.path_length);
        bytes.extend_from_slice(self.path.as_bytes());

        // Write the nonce
        bytes.push(self.nonce.len() as u8);
        bytes.extend_from_slice(&self.nonce);

        // Write the algorithm
        bytes.push(self.algorithm as u8);

        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut offset = 0;

        // Read the path
        let path_length = bytes[offset];
        offset += 1;

        let mut path = Vec::new();
        path.extend_from_slice(&bytes[offset..offset + path_length as usize]);
        offset += path_length as usize;

        // Read the nonce
        let nonce_length = bytes[offset];
        offset += 1;

        let mut nonce = Vec::new();
        nonce.extend_from_slice(&bytes[offset..offset + nonce_length as usize]);
        offset += nonce_length as usize;

        // Read the algorithm
        let algorithm = bytes[offset];

        Self {
            path_length,
            path: String::from_utf8(path).unwrap(),
            nonce,
            algorithm: Algorithm::from_bytes(&[algorithm])
        }
    }
}