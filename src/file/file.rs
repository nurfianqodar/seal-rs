use std::{fs, io, path};

use crate::{
    chunk::RequiredChunk,
    file::{Header, reader_has_magic},
    result::Result,
};

pub struct PlainFileReader {
    inner: fs::File,
}

impl PlainFileReader {
    pub fn open<P>(path: P) -> Result<Self>
    where
        P: AsRef<path::Path>,
    {
        let mut inner = fs::OpenOptions::new()
            .read(true)
            .create(false)
            .write(false)
            .open(path)?;
        if reader_has_magic(&mut inner)? {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "file was encrypted").into());
        }
        Ok(Self { inner })
    }

    pub fn reader(&mut self) -> io::BufReader<&mut fs::File> {
        io::BufReader::new(&mut self.inner)
    }
}

pub struct CipherFileReader {
    header: Header,
    inner: fs::File,
}

impl CipherFileReader {
    pub fn open<P>(path: P) -> Result<Self>
    where
        P: AsRef<path::Path>,
    {
        let mut inner = fs::OpenOptions::new()
            .read(true)
            .create(false)
            .write(false)
            .open(path)?;
        if !reader_has_magic(&mut inner)? {
            return Err(
                io::Error::new(io::ErrorKind::InvalidData, "file was not encrypted").into(),
            );
        }
        let header = Header::read_from(&mut inner)?;
        Ok(Self { inner, header })
    }

    pub fn reader(&mut self) -> io::BufReader<&mut fs::File> {
        io::BufReader::new(&mut self.inner)
    }
}

pub struct FileWriter {
    inner: fs::File,
}

impl FileWriter {
    pub fn create<P>(path: P, overwrite: bool) -> Result<Self>
    where
        P: AsRef<path::Path>,
    {
        let mut opts = fs::OpenOptions::new();
        opts.write(true);
        if overwrite {
            opts.create(true).truncate(true);
        } else {
            opts.create_new(true);
        }
        let inner = opts.open(path)?;
        Ok(Self { inner })
    }

    pub fn writer(&mut self) -> io::BufWriter<&mut fs::File> {
        io::BufWriter::new(&mut self.inner)
    }
}
