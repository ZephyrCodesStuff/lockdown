use std::{io::{Read, Write}, path::PathBuf, sync::{Arc, Mutex}};

use file::EncryptedFile;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};

mod aes;
mod file;

fn add_folder_recursive(files: &mut Vec<PathBuf>, folder: PathBuf) {
    let folder = std::fs::read_dir(&folder).unwrap();
    let files_mutex = Arc::new(Mutex::new(files));

    folder
        .into_iter()
        .map(|file| file.unwrap().path())
        .collect::<Vec<PathBuf>>()
        .par_iter()
        .for_each(|file| {
            let path = PathBuf::from(file);

            // Ignore symlinks
            if path.is_symlink() { return; }
            
            let mut files = files_mutex.lock().unwrap();
            
            if path.is_dir() {
                add_folder_recursive(&mut files, path);
                return;
            }

            // Ignore files that start with the magic bytes (already encrypted)
            let mut file = std::fs::File::open(&path).unwrap();
            let mut magic = [0; 8];
            file.read_exact(&mut magic).unwrap();

            if &magic == file::MAGIC { return; }

            files.push(path);
        });
}

enum Mode {
    Normal,
    Replace,
}

impl From<&str> for Mode {
    fn from(s: &str) -> Self {
        match s {
            "normal" => Self::Normal,
            "replace" => Self::Replace,
            _ => panic!("Invalid mode")
        }
    }
}

const USAGE: &str = "Usage: lockdown <folder> <mode: normal/replace>";

fn main() {
    let root = std::env::args().nth(1).expect(USAGE);
    let mode = std::env::args().nth(2).expect(USAGE);

    let mode = Mode::from(mode.as_str());
    
    // Enumerate all files in the root folder
    let mut files: Vec<PathBuf> = vec![];
    add_folder_recursive(&mut files, root.into());

    // Encrypt the files
    for file in files {
        let path_str = file.as_path().to_str().unwrap().to_string();
        let encrypted = EncryptedFile::from(path_str.clone());
        
        match mode {
            Mode::Normal => {
                let output_path = format!("{}.{}", path_str, file::EXTENSION);

                let mut output = std::fs::File::create(output_path).unwrap();
                output.write_all(&encrypted.to_bytes()).unwrap();
            },
            Mode::Replace => {
                std::fs::remove_file(&file).unwrap();
                
                let mut output = std::fs::File::create(file).unwrap();
                output.write_all(&encrypted.to_bytes()).unwrap();
            }
        }
    }
}