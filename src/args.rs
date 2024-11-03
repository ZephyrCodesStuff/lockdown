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

// Useful to make `Mode` not depend on `Command`
pub trait CryptCommand {
    fn encrypt(&self) -> bool;
    fn input(&self) -> &PathBuf;
    fn output(&self) -> &PathBuf;
    
    fn execute(&self);
}

#[derive(Subcommand, PartialEq, Eq, Clone)]
pub enum Command {
    Encrypt(EncryptArgs),
    Decrypt(DecryptArgs),
}

impl CryptCommand for Command {
    fn encrypt(&self) -> bool {
        match self {
            Self::Encrypt(_) => true,
            Self::Decrypt(_) => false,
        }
    }

    fn input(&self) -> &PathBuf {
        match self {
            Self::Encrypt(args) => &args.input,
            Self::Decrypt(args) => &args.input,
        }
    }

    fn output(&self) -> &PathBuf {
        match self {
            Self::Encrypt(args) => &args.output,
            Self::Decrypt(args) => &args.output,
        }
    }

    fn execute(&self) {
        Mode::from((self.input().clone(), self.output().clone())).execute(self);
    }
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

impl Mode {
    pub fn execute(&self, command: &dyn CryptCommand) {
        match self {
            Self::File => crate::file_mode(command.encrypt(), command.input().clone(), command.output().clone()),
            Self::Folder => crate::folder_mode(command.encrypt(), command.input().clone(), command.output().clone()),
        }
    }
}