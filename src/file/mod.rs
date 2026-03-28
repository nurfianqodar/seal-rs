use crate::result::Result;
use crate::{core::reader_has_magic, error::Error};
use std::{fs, path};

pub trait SealFile {
    fn open_plaintext_file<P>(path: P) -> Result<fs::File>
    where
        P: AsRef<path::Path>;

    fn open_ciphertext_file<P>(path: P) -> Result<fs::File>
    where
        P: AsRef<path::Path>;

    fn create_out_file<P>(path: P) -> Result<fs::File>
    where
        P: AsRef<path::Path>;
}

impl SealFile for fs::File {
    fn open_plaintext_file<P>(path: P) -> Result<fs::File>
    where
        P: AsRef<path::Path>,
    {
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(false)
            .create(false)
            .open(path)?;
        if reader_has_magic(&mut file)? {
            return Err(Error::Encrypted);
        }
        Ok(file)
    }

    fn open_ciphertext_file<P>(path: P) -> Result<fs::File>
    where
        P: AsRef<path::Path>,
    {
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(false)
            .create(false)
            .open(path)?;
        if !reader_has_magic(&mut file)? {
            return Err(Error::NotEncrypted);
        }
        Ok(file)
    }

    fn create_out_file<P>(path: P) -> Result<fs::File>
    where
        P: AsRef<path::Path>,
    {
        let file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(path)?;
        Ok(file)
    }
}
