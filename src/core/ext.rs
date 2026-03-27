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
