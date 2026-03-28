use crate::core::RequiredChunk;
use crate::result::Result;

impl RequiredChunk for u64 {
    fn read_from<R>(reader: &mut R) -> Result<Self>
    where
        R: std::io::Read,
    {
        let mut buf = [0u8; 8];
        reader.read_exact(&mut buf)?;
        let v = u64::from_le_bytes(buf);
        Ok(v)
    }

    fn write_to<W>(&self, writer: &mut W) -> Result<()>
    where
        W: std::io::Write,
    {
        writer.write_all(&self.to_le_bytes())?;
        Ok(())
    }
}

impl RequiredChunk for u32 {
    fn read_from<R>(reader: &mut R) -> Result<Self>
    where
        R: std::io::Read,
    {
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf)?;
        let v = u32::from_le_bytes(buf);
        Ok(v)
    }

    fn write_to<W>(&self, writer: &mut W) -> Result<()>
    where
        W: std::io::Write,
    {
        writer.write_all(&self.to_le_bytes())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use crate::{core::chunk::RequiredChunk, result::Result};

    #[test]
    fn write_read_u32() -> Result<()> {
        let mut buf = Vec::<u8>::new();
        let mut cursor = io::Cursor::new(&mut buf);

        let value = 1024u32;
        value.write_to(&mut cursor)?;

        let mut cursor2 = io::Cursor::new(&mut buf);
        let readed_value = u32::read_from(&mut cursor2)?;
        assert!(readed_value == value);
        Ok(())
    }

    #[test]
    fn write_read_u64() -> Result<()> {
        let mut buf = Vec::<u8>::new();
        let mut cursor = io::Cursor::new(&mut buf);

        let value = 1024u64;
        value.write_to(&mut cursor)?;

        let mut cursor2 = io::Cursor::new(&mut buf);
        let readed_value = u64::read_from(&mut cursor2)?;
        assert!(readed_value == value);
        Ok(())
    }
}
