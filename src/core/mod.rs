mod chunk;
mod ext;
mod header;
mod util;

use crate::result::Result;
use chunk::*;
use header::*;
use std::io;

const MAGIC_LEN: usize = 16;
const MAGIC: [u8; MAGIC_LEN] = [
    0xde, 0xad, 0xbe, 0xef, // 4
    0xde, 0xad, 0xbe, 0xef, // 4
    0xde, 0xad, 0xbe, 0xef, // 4
    0xde, 0xad, 0xbe, 0xef, // 4
];

const VERSION_LEN: usize = 3;
const VERSION: [u8; VERSION_LEN] = [0, 1, 0];
pub const VERSION_STRING: &str = "0.1.0";
const FILE_ID_LEN: usize = 8;
const SALT_LEN: usize = 16;
const ARGON2_VERSION: argon2::Version = argon2::Version::V0x13;
const TIME_COST: u32 = 3;

#[cfg(not(test))]
const MEMORY_COST: u32 = 1024 * 128;

#[cfg(test)]
const MEMORY_COST: u32 = 1024;

const PARALLELISM: u32 = 2;

#[cfg(not(test))]
const CHUNK_SIZE: usize = 1024 * 512;

#[cfg(test)]
const CHUNK_SIZE: usize = 1024 * 10;

pub fn encrypt<R, W>(reader: &mut R, writer: &mut W, password: &str) -> Result<()>
where
    R: io::Read,
    W: io::Write,
{
    let header = Header::new(ARGON2_VERSION, TIME_COST, MEMORY_COST, PARALLELISM);
    header.write_to(writer)?;
    let mut cipher = header.gen_cipher(password)?;
    while let Some(plaintext) = PlainText::<CHUNK_SIZE>::read_from(reader)? {
        let ciphertext = plaintext.encrypt(&header, &mut cipher)?;
        ciphertext.write_to(writer)?;
    }
    Ok(())
}

pub fn decrypt<R, W>(reader: &mut R, writer: &mut W, password: &str) -> Result<()>
where
    R: io::Read,
    W: io::Write,
{
    let header = Header::read_from(reader)?;
    let mut cipher = header.gen_cipher(password)?;
    while let Some(ciphertext) = CipherText::<CHUNK_SIZE>::read_from(reader)? {
        let plaintext = ciphertext.decrypt(&header, &mut cipher)?;
        plaintext.write_to(writer)?;
    }
    Ok(())
}

/// Be careful this finction change seek to 0
pub fn reader_has_magic<R>(reader: &mut R) -> Result<bool>
where
    R: io::Read + io::Seek,
{
    let mut magic = [0u8; MAGIC_LEN];
    reader.seek(io::SeekFrom::Start(0))?;
    let mut readn = 0usize;
    while readn < magic.len() {
        let n = reader.read(&mut magic[readn..])?;
        if n == 0 {
            break;
        }
        readn += n;
    }
    reader.seek(io::SeekFrom::Start(0))?;
    if readn != magic.len() {
        return Ok(false);
    }

    Ok(magic == MAGIC)
}

#[cfg(test)]
mod tests {
    use std::io::{self, Write};

    use crate::{
        core::{decrypt, encrypt},
        error::Error,
        result::Result,
    };

    #[test]
    fn encrypt_decrypt_success() -> Result<()> {
        let msg = b"Hello world!";
        let mut buf_plain = Vec::from(msg);
        let mut buf_cipher = Vec::<u8>::new();
        let mut reader = io::Cursor::new(&mut buf_plain);
        let mut writer = io::Cursor::new(&mut buf_cipher);
        let password = "secretpassword";
        encrypt(&mut reader, &mut writer, password)?;

        let mut buf_plain2 = Vec::from(msg);
        let mut reader = io::Cursor::new(&mut buf_cipher);
        let mut writer = io::Cursor::new(&mut buf_plain2);
        decrypt(&mut reader, &mut writer, password)?;

        assert!(buf_plain == buf_plain2);
        Ok(())
    }

    #[test]
    fn encrypt_decrypt_corrupted() -> Result<()> {
        let msg = b"Hello world!";
        let mut buf_plain = Vec::from(msg);
        let mut buf_cipher = Vec::<u8>::new();
        let mut reader = io::Cursor::new(&mut buf_plain);
        let mut writer = io::Cursor::new(&mut buf_cipher);
        let password = "secretpassword";
        encrypt(&mut reader, &mut writer, password)?;
        writer.write_all(b"corruptor")?;

        let mut buf_plain2 = Vec::from(msg);
        let mut reader = io::Cursor::new(&mut buf_cipher);
        let mut writer = io::Cursor::new(&mut buf_plain2);
        let result = decrypt(&mut reader, &mut writer, password);

        assert!(result.is_err());
        if let Err(e) = result {
            assert!(e == Error::FileCorrupt);
        }
        Ok(())
    }
}
