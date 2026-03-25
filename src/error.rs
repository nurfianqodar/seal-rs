use std::io;

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
