use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

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
    /// The input path
    pub input: PathBuf,

    /// The output path
    pub output: PathBuf,
}

#[derive(Parser, PartialEq, Eq, Clone)]
pub struct DecryptArgs {
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

impl From<(PathBuf, PathBuf)> for Mode {
    fn from(paths: (PathBuf, PathBuf)) -> Self {
        if paths.0.is_file() && (paths.1.is_file() || !paths.1.exists()) {
            Self::File
        } else if paths.0.is_dir() && (paths.1.is_dir() || !paths.1.exists()) {
            Self::Folder
        } else {
            panic!("Input and output paths must be of the same type");
        }
    }

}