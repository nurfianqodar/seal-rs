use std::{fmt, io};

#[derive(Debug)]
pub enum Error {
    Unknown,
    OutOfMemory,
    DecryptFailed,
    EncryptFailed,
    EmptyPassword,
    FileCorrupt,
    NotEncrypted,
    Encrypted,
    NotFound,
    IsADirectory,
    PermissionDenied,
    AlreadyExists,
    IncompatibleVersion,
    InvalidArgon2Param,
    InvalidArgon2Version,
    InvalidMagic,
    KeyDerivation,
    WriteSizeOverflow,
    NotAFile,
    PasswordNotMatch,
    VerificationFailed,
    StorageFull,
}

impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        match value.kind() {
            io::ErrorKind::NotFound => Self::NotFound,
            io::ErrorKind::IsADirectory => Self::IsADirectory,
            io::ErrorKind::PermissionDenied => Self::PermissionDenied,
            io::ErrorKind::UnexpectedEof => Self::FileCorrupt,
            io::ErrorKind::AlreadyExists => Self::AlreadyExists,
            io::ErrorKind::OutOfMemory => Self::OutOfMemory,
            io::ErrorKind::StorageFull => Self::StorageFull,
            _ => Self::Unknown,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.msg())
    }
}

impl std::error::Error for Error {}

impl Error {
    pub fn msg(&self) -> &'static str {
        match self {
            Self::IsADirectory | Self::NotAFile => "not a file",
            Self::AlreadyExists => "file already exists",
            Self::DecryptFailed => "decryption failed",
            Self::EncryptFailed => "encryption failed",
            Self::EmptyPassword => "password is empty",
            Self::FileCorrupt => "file was corrupt or changed",
            Self::NotEncrypted | Self::InvalidMagic => "file was not encrypted",
            Self::Encrypted => "file already encrypted",
            Self::PermissionDenied => "permission denied",
            Self::IncompatibleVersion => "incompatible version",
            Self::NotFound => "file not found",
            Self::PasswordNotMatch => "password not match",
            Self::VerificationFailed => "verification failed",
            Self::OutOfMemory => "out of memory",
            Self::StorageFull => "storage full",
            Self::InvalidArgon2Param
            | Self::InvalidArgon2Version
            | Self::WriteSizeOverflow
            | Self::KeyDerivation
            | Self::Unknown => "unknown internal error",
        }
    }
}
