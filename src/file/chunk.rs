use std::io;

use crate::chunk::{OptionalChunk, RequiredChunk};

#[derive(Debug)]
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
        return Ok(Some(Self { buf, len: readn }));
    }

    fn write_to<W>(&self, writer: &mut W) -> crate::result::Result<()>
    where
        W: std::io::Write,
        Self: Sized,
    {
        if self.len == 0 {
            return Ok(());
        }
        writer.write_all(&self.buf[..self.len])?;
        Ok(())
    }
}

pub const TAG_LEN: usize = 16;
pub const ID_LEN: usize = 4;

#[derive(Debug)]
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
        let mut readn = 0usize;
        while readn < id.len() {
            let n = reader.read(&mut id[readn..])?;
            if n == 0 {
                break;
            }
            readn += n;
        }
        if readn == 0 {
            return Ok(None);
        }
        if readn < id.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "unexpected eof while reading ciphertext chunk",
            )
            .into());
        }
        let len = u64::read_from(reader)? as usize;
        if len > S {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "length of buffer information is larger than chunk buffer",
            )
            .into());
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
        writer.write_all(&self.id)?;
        (self.len as u64).write_to(writer)?;
        writer.write_all(&self.buf[..self.len])?;
        writer.write_all(&self.tag)?;
        Ok(())
    }
}

impl<const S: usize> CipherText<S> {
    pub fn id(&self) -> [u8; 4] {
        self.id
    }
}
