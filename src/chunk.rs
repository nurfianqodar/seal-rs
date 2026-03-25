use std::io;

use crate::result::Result;

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
