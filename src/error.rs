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
            Self::Io(e) => write!(f, "io error: {e}"),
            Self::Argon2(e) => write!(f, "argon2 error: {e}"),
            Self::Aes(e) => write!(f, "aes error: {e}"),
        }
    }
}

impl std::error::Error for Error {}
