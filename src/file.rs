use std::{fs::File, io::{BufReader, BufWriter, Cursor, Read, Seek, Write}, path::PathBuf};

use aes_gcm::aead::Payload;

use crate::aes::{Keys, AES};

// b"LOCKDOWN" as u64
pub const MAGIC: u64 = 0x_2003_05_24___2005_12_15;
const MAX_CHUNK_SIZE: usize = 1024 * 1024 * 10; // 10MB

#[allow(dead_code)]
pub struct EncryptedFile {
    pub header_nonce: [u8; 12],
    pub header_crc32: [u8; 4],

    pub header: Header,
    pub header_plaintext: Vec<u8>,
    pub header_ciphertext: Vec<u8>,

    pub plaintext: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

pub struct Header {
    pub path: String,

    pub content_nonce: [u8; 12],
    pub content_crc32: [u8; 4],
}

impl EncryptedFile {
    pub fn is_encrypted(path: &PathBuf) -> bool {
        let mut file = File::open(path).unwrap();
        let mut magic_hash = [0; 20];

        match file.read_exact(&mut magic_hash) {
            Ok(_) => {},
            Err(e) => match e.kind() {
                // File is too small to contain magic hash -- not encrypted
                std::io::ErrorKind::UnexpectedEof => return false,
                _ => panic!("Failed to read magic hash: {}", e),
            }
        }

        let mut hasher = sha1_smol::Sha1::new();
        
        // Read file in chunks
        let mut buffer = vec![0; MAX_CHUNK_SIZE];
        loop {
            let bytes_read = file.read(&mut buffer).unwrap();
            if bytes_read == 0 {
                break;
            }

            hasher.update(&buffer[..bytes_read]);
        }

        hasher.update(&MAGIC.to_le_bytes());

        hasher.digest().bytes() == magic_hash
    }

    pub fn new(path: PathBuf) -> Self {
        let mut plaintext = Vec::new();
        let mut file = File::open(path.clone()).unwrap();
        file.read_to_end(&mut plaintext).unwrap();

        // Encrypt the file
        let aes = AES::new(Keys::Content);
        let content_encryption_result = aes.encrypt_ctr(&mut plaintext);

        let path_str = path.to_str().unwrap();

        let header = Header {
            path: path_str.to_string(),

            content_nonce: content_encryption_result.nonce,
            content_crc32: content_encryption_result.aad,
        };

        // Encrypt the header
        let header_bytes = header.to_bytes();
        let aes = AES::new(Keys::Header);
        let header_encryption_result = aes.encrypt_ctr(&header_bytes);

        Self {
            header_nonce: header_encryption_result.nonce,
            header_crc32: header_encryption_result.aad,
            
            header,
            header_plaintext: header_bytes,
            header_ciphertext: header_encryption_result.ciphertext,

            plaintext,
            ciphertext: content_encryption_result.ciphertext,
        }
    }
}

impl EncryptedFile {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer_data = Vec::new();
        
        {
            let mut writer = BufWriter::new(&mut buffer_data);

            writer.write_all(&self.header_nonce).unwrap();
            writer.write_all(&self.header_crc32).unwrap();

            writer.write_all(&(self.header_ciphertext.len() as u16).to_le_bytes()).unwrap();
            writer.write_all(&self.header_ciphertext).unwrap();

            writer.write_all(&(self.ciphertext.len() as u64).to_le_bytes()).unwrap();
            writer.write_all(&self.ciphertext).unwrap();

            writer.flush().unwrap();
        }

        let mut buffer_magic = Vec::new();
        
        {
            let mut writer = BufWriter::new(&mut buffer_magic);

            // Calculate magic hash
            let mut hasher = sha1_smol::Sha1::new();

            hasher.update(&buffer_data);
            hasher.update(&MAGIC.to_le_bytes());

            let magic_hash = hasher.digest().bytes();
            writer.write_all(&magic_hash).unwrap();

            writer.flush().unwrap();
        }

        buffer_magic.extend(buffer_data);

        buffer_magic
    }

    #[allow(dead_code)]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let mut reader = Cursor::new(bytes);

        // Skip magic hash
        reader.seek(std::io::SeekFrom::Start(20)).unwrap();

        let mut header_nonce = [0; 12];
        reader.read_exact(&mut header_nonce).unwrap();

        let mut header_crc32 = [0; 4];
        reader.read_exact(&mut header_crc32).unwrap();

        let mut header_length = [0; 2];
        reader.read_exact(&mut header_length).unwrap();

        let mut header_ciphertext = vec![0; u16::from_le_bytes(header_length) as usize];
        reader.read_exact(&mut header_ciphertext).unwrap();

        let mut ciphertext_length = [0; 8];
        reader.read_exact(&mut ciphertext_length).unwrap();

        let mut ciphertext = vec![0; u64::from_le_bytes(ciphertext_length) as usize];
        reader.read_exact(&mut ciphertext).unwrap();

        // Decrypt header
        let aes = AES::new(Keys::Header);
        let header_payload = Payload {
            aad: &header_crc32,
            msg: &header_ciphertext,
        };
        let header_bytes = aes.decrypt_ctr(header_payload, &header_nonce).unwrap();
        let header = Header::from_bytes(&header_bytes);

        // Decrypt content
        let aes = AES::new(Keys::Content);
        let content_payload = Payload {
            aad: &header.content_crc32,
            msg: &ciphertext,
        };

        let plaintext = aes.decrypt_ctr(content_payload, &header.content_nonce).unwrap();

        // Check plaintext CRC32
        let mut crc32 = crc32fast::Hasher::new();
        crc32.update(&plaintext);
        if crc32.finalize().to_le_bytes() != header.content_crc32 {
            return Err("Invalid CRC32".to_string());
        }

        Ok(Self {
            header_nonce,
            header_crc32,
            
            header,
            header_plaintext: header_bytes,
            header_ciphertext,
            
            plaintext,
            ciphertext,
        })
    }
}

impl Header {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        
        {
            let mut writer = BufWriter::new(&mut buffer);

            writer.write_all(&(self.path.len() as u32).to_le_bytes()).unwrap();
            writer.write_all(self.path.as_bytes()).unwrap();

            writer.write_all(&self.content_nonce).unwrap();
            writer.write_all(&self.content_crc32).unwrap();

            writer.flush().unwrap();
        }

        buffer
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut reader = BufReader::new(bytes);

        let mut path_length = [0; 4];
        reader.read_exact(&mut path_length).unwrap();

        let mut path = vec![0; u32::from_le_bytes(path_length) as usize];
        reader.read_exact(&mut path).unwrap();

        let path = String::from_utf8(path).unwrap();

        let mut content_nonce = [0; 12];
        reader.read_exact(&mut content_nonce).unwrap();

        let mut content_crc32 = [0; 4];
        reader.read_exact(&mut content_crc32).unwrap();

        Self {
            path,

            content_nonce,
            content_crc32,
        }
    }
}