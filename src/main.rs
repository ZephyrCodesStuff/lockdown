use std::{fs::File, io::{Read, Write}, path::PathBuf};

use args::{Args, CryptCommand};
use clap::Parser;
use file::EncryptedFile;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use utils::add_folder_recursive;

mod args;
mod aes;
mod file;
mod utils;

fn main() {
    let args = Args::parse();

    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }

    pretty_env_logger::init();

    args.command.execute();
}

fn file_mode(encrypt: bool, input: PathBuf, output: PathBuf) {
    // Ensure both input and output paths are files
    if !input.is_file() {
        log::error!("Input path is not a file");
        std::process::exit(1);
    }

    if output.is_dir() {
        log::error!("Output path is a directory");
        std::process::exit(1);
    }

    // Ignore the input file if it's already encrypted (or vice versa)
    if encrypt && EncryptedFile::is_encrypted(&input) {
        log::warn!("Ignoring encrypted file: {}", input.to_str().unwrap());
        return;
    } else if !encrypt && !EncryptedFile::is_encrypted(&input) {
        log::warn!("Ignoring unencrypted file: {}", input.to_str().unwrap());
        return;
    }

    let input_path = input.as_path().to_str().unwrap().to_string();
    let mut output = std::fs::File::create(output).unwrap();

    // Process the input file
    if encrypt {
        let encrypted = EncryptedFile::new(input);
        output.write_all(&encrypted.to_bytes()).unwrap();
    } else {
        let ciphertext = File::open(input).unwrap();
        let ciphertext = std::io::BufReader::new(ciphertext).bytes().collect::<Result<Vec<u8>, _>>().unwrap();

        let encrypted = EncryptedFile::from_bytes(&ciphertext);

        if let Err(e) = encrypted {
            log::error!("Failed to decrypt file: {}", e);
            std::process::exit(1);
        }

        let encrypted = encrypted.unwrap();
        output.write_all(&encrypted.plaintext).unwrap();
    }

    let action = if encrypt { "Encrypted" } else { "Decrypted" };
    log::info!("{} file: {}", action, input_path);
}

fn folder_mode(encrypt: bool, input: PathBuf, output: PathBuf) {
    // Ensure the input path is a directory
    if !input.is_dir() {
        log::error!("Input path is not a directory");
        std::process::exit(1);
    }

    // Ensure the output path is a directory
    if output.is_file() {
        log::error!("Output path is a file");
        std::process::exit(1);
    }

    // Create the output directory if it doesn't exist
    if !output.exists() {
        std::fs::create_dir_all(&output).unwrap();
    }

    // Enumerate all files in the root folder
    let mut files: Vec<PathBuf> = vec![];
    add_folder_recursive(&mut files, input.clone());

    // Process each file
    files.par_iter().for_each(|file| {
        let relative_output = file.strip_prefix(&input).unwrap();
        let output_path = output.join(relative_output);

        // Create the output directory if it doesn't exist
        if let Some(parent) = output_path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent).unwrap();
            }
        }

        // Process the file
        file_mode(encrypt, file.clone(), output_path);
    });
}