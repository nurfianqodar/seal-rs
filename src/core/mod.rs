mod chunk;
mod ext;
mod header;
mod util;

use std::io;

use chunk::*;
use header::*;

use crate::result::Result;

const MAGIC_LEN: usize = 16;
const MAGIC: [u8; MAGIC_LEN] = [
    0xde, 0xad, 0xbe, 0xef, // 4
    0xde, 0xad, 0xbe, 0xef, // 4
    0xde, 0xad, 0xbe, 0xef, // 4
    0xde, 0xad, 0xbe, 0xef, // 4
];

const VERSION_LEN: usize = 3;
const VERSION: [u8; VERSION_LEN] = [0, 1, 0];
const FILE_ID_LEN: usize = 8;
const SALT_LEN: usize = 16;
const ARGON2_VERSION: argon2::Version = argon2::Version::V0x13;
const TIME_COST: u32 = 3;
const MEMORY_COST: u32 = 1024 * 128;
const PARALLELISM: u32 = 2;
const CHUNK_SIZE: usize = 1024 * 256;

pub fn encrypt<R, W>(reader: &mut R, writer: &mut W, password: &str) -> Result<()>
where
    R: io::Read,
    W: io::Write,
{
    let mut rng = rand::rng();
    let header = Header::new(
        &mut rng,
        ARGON2_VERSION,
        TIME_COST,
        MEMORY_COST,
        PARALLELISM,
    );
    header.write_to(writer)?;
    let mut cipher = header.gen_cipher(password)?;
    while let Some(plaintext) = PlainText::<CHUNK_SIZE>::read_from(reader)? {
        let ciphertext = plaintext.encrypt(&mut rng, &header, &mut cipher)?;
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
