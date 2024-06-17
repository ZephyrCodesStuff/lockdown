use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

use crate::file::MAGIC_NUMBERS;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
pub struct Args {
    /// Whether to encrypt or decrypt the input
    #[command(subcommand)]
    pub command: Command,

    
}

#[derive(Subcommand, PartialEq, Eq, Clone)]
pub enum Command {
    Encrypt(EncryptArgs),
    Decrypt(DecryptArgs),
}

#[derive(Parser, PartialEq, Eq, Clone)]
pub struct EncryptArgs {
    /// Mode to run the program in
    pub mode: Mode,
    
    /// The input path
    pub input: PathBuf,

    /// The output path
    pub output: PathBuf,

    /// Whether to create an output file with a visible or concealed magic number
    #[clap(long, short, default_value = "visible")]
    pub magic: Magic,
}

#[derive(Parser, PartialEq, Eq, Clone)]
pub struct DecryptArgs {
    /// Mode to run the program in
    pub mode: Mode,

    /// The input path
    pub input: PathBuf,

    /// The output path
    pub output: PathBuf,
}

#[derive(Parser, ValueEnum, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    File,
    Folder,
}

#[derive(Parser, ValueEnum, Clone, Copy, PartialEq, Eq)]
pub enum Magic {
    Visible,
    Hidden,
}

impl Magic {
    pub fn to_bytes(&self) -> [u8; 8] {
        match self {
            Self::Visible => *b"LOCKDOWN",
            Self::Hidden => {
                let index = rand::random::<usize>() % MAGIC_NUMBERS.len();
                MAGIC_NUMBERS[index].to_le_bytes()
            }
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes == *b"LOCKDOWN" {
            Ok(Self::Visible)
        } else {
            let mut magic = [0; 8];
            magic.copy_from_slice(&bytes[..8]);

            let magic = u64::from_le_bytes(magic);
            MAGIC_NUMBERS.iter().any(|&number| number == magic)
                .then(|| Self::Hidden)
                .ok_or("Invalid magic")
        }
    }
}