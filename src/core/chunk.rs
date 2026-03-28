use crate::core::{
    Header,
    util::{self, new_id},
};
use crate::error::Error;
use crate::result::Result;
use aes_gcm::aead::AeadMutInPlace;
use std::io;

// Error will be returned if the chunk is not filled at all
// when reading
pub trait RequiredChunk {
    fn read_from<R>(reader: &mut R) -> Result<Self>
    where
        R: io::Read,
        Self: Sized;

    fn write_to<W>(&self, writer: &mut W) -> Result<()>
    where
        W: io::Write,
        Self: Sized;
}

// None will be returned if the chunk is not filled at all
// instead of error when reading
pub trait OptionalChunk {
    fn read_from<R>(reader: &mut R) -> Result<Option<Self>>
    where
        R: io::Read,
        Self: Sized;

    fn write_to<W>(&self, writer: &mut W) -> Result<()>
    where
        W: io::Write,
        Self: Sized;
}

#[derive(Debug, zeroize::ZeroizeOnDrop, zeroize::Zeroize)]
pub struct PlainText<const S: usize> {
    buf: [u8; S],
    len: usize,
}

impl<const S: usize> OptionalChunk for PlainText<S> {
    fn read_from<R>(reader: &mut R) -> crate::result::Result<Option<Self>>
    where
        R: std::io::Read,
        Self: Sized,
    {
        let mut buf = [0u8; S];
        let mut readn = 0usize;
        while readn < S {
            let n = reader.read(&mut buf[readn..])?;
            if n == 0 {
                break;
            }
            readn += n;
        }
        if readn == 0 {
            return Ok(None);
        }
        Ok(Some(Self { buf, len: readn }))
    }

    fn write_to<W>(&self, writer: &mut W) -> crate::result::Result<()>
    where
        W: std::io::Write,
        Self: Sized,
    {
        if self.len == 0 {
            return Ok(());
        }
        if self.len > S {
            return Err(Error::WriteSizeOverflow);
        }
        writer.write_all(&self.buf[..self.len])?;
        Ok(())
    }
}

impl<const S: usize> PlainText<S> {
    pub fn encrypt(
        mut self,
        header: &Header,
        cipher: &mut aes_gcm::Aes256Gcm,
    ) -> Result<CipherText<S>> {
        let id = new_id();
        let nonce = header.gen_nonce(id);
        let tag = cipher
            .encrypt_in_place_detached((&nonce).into(), &id, &mut self.buf[..self.len])
            .map_err(|_| Error::EncryptFailed)?;
        Ok(CipherText {
            id,
            buf: self.buf,
            len: self.len,
            tag: tag.into(),
        })
    }
}

pub const TAG_LEN: usize = 16;
pub const ID_LEN: usize = util::ID_LEN;

#[derive(Debug, zeroize::ZeroizeOnDrop, zeroize::Zeroize)]
pub struct CipherText<const S: usize> {
    id: [u8; ID_LEN],
    buf: [u8; S],
    len: usize,
    tag: [u8; TAG_LEN],
}

impl<const S: usize> OptionalChunk for CipherText<S> {
    fn read_from<R>(reader: &mut R) -> crate::result::Result<Option<Self>>
    where
        R: std::io::Read,
        Self: Sized,
    {
        let mut id = [0u8; ID_LEN];
        let n = reader.read(&mut id)?;
        if n == 0 {
            return Ok(None);
        }
        let mut readn = n;
        while readn < id.len() {
            let n = reader.read(&mut id[readn..])?;
            if n == 0 {
                return Err(Error::FileCorrupt);
            }
            readn += n;
        }
        let len = u64::read_from(reader)? as usize;
        if len > S {
            return Err(Error::FileCorrupt);
        }
        let mut buf = [0u8; S];
        reader.read_exact(&mut buf[..len])?;
        let mut tag = [0u8; TAG_LEN];
        reader.read_exact(&mut tag)?;

        Ok(Some(Self { id, buf, len, tag }))
    }

    fn write_to<W>(&self, writer: &mut W) -> crate::result::Result<()>
    where
        W: std::io::Write,
        Self: Sized,
    {
        if self.len == 0 {
            return Ok(());
        }
        if self.len > S {
            return Err(Error::WriteSizeOverflow);
        }
        writer.write_all(&self.id)?;
        (self.len as u64).write_to(writer)?;
        writer.write_all(&self.buf[..self.len])?;
        writer.write_all(&self.tag)?;
        Ok(())
    }
}

impl<const S: usize> CipherText<S> {
    pub fn decrypt(
        mut self,
        header: &Header,
        cipher: &mut aes_gcm::Aes256Gcm,
    ) -> Result<PlainText<S>> {
        let nonce = header.gen_nonce(self.id);
        cipher
            .decrypt_in_place_detached(
                (&nonce).into(),
                &self.id,
                &mut self.buf[..self.len],
                (&self.tag).into(),
            )
            .map_err(|_| Error::DecryptFailed)?;
        Ok(PlainText {
            buf: self.buf,
            len: self.len,
        })
    }
}
