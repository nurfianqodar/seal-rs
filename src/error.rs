use std::{fmt, io};

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Argon2(argon2::Error),
    Aes(aes_gcm::Error),
}

impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<argon2::Error> for Error {
    fn from(value: argon2::Error) -> Self {
        Self::Argon2(value)
    }
}

impl From<aes_gcm::Error> for Error {
    fn from(value: aes_gcm::Error) -> Self {
        Self::Aes(value)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{}", io_msg(e.kind())),
            Self::Argon2(_e) => write!(f, "invalid key derivation parameter(s)"),
            Self::Aes(_e) => write!(f, "decryption failed"),
        }
    }
}

impl std::error::Error for Error {}

fn io_msg(kind: io::ErrorKind) -> &'static str {
    match kind {
        io::ErrorKind::NotFound => "file not found",
        io::ErrorKind::PermissionDenied => "permission denied",
        io::ErrorKind::AlreadyExists => "file already exists",
        io::ErrorKind::InvalidInput => "invalid input",
        io::ErrorKind::InvalidData => "incompatible file",
        io::ErrorKind::UnexpectedEof => "data was corrupt",
        io::ErrorKind::WriteZero => "failed to write file",
        io::ErrorKind::OutOfMemory => "out of memory",
        io::ErrorKind::Interrupted => "operation interrupted",
        io::ErrorKind::Unsupported => "operation not supported",
        io::ErrorKind::TimedOut => "operation timed out",
        io::ErrorKind::WouldBlock => "resource temporarily unavailable",
        _ => "i/o error",
    }
}
