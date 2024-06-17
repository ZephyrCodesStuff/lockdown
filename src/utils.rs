use std::{io::Read, path::PathBuf, sync::{Arc, Mutex}};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};


pub fn add_folder_recursive(files: &mut Vec<PathBuf>, folder: PathBuf) {
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

            // Check if file is too small (< 8 bytes)
            if path.metadata().unwrap().len() < 8 {
                log::warn!("Ignoring file: {} (too small)", path.to_str().unwrap());
                return;
            }

            // Ignore files that start with the magic bytes (already encrypted)
            let mut file = std::fs::File::open(&path).unwrap();
            let mut magic = [0; 8];
            file.read_exact(&mut magic).unwrap();

            files.push(path);
        });
}