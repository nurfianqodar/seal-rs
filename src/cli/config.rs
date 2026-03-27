use crate::cli::action::{Decrypt, Encrypt, Verify};

#[derive(Debug, clap::Parser)]
pub struct Config {
    #[command(subcommand)]
    pub mode: Mode,
}

#[derive(Debug, Clone, clap::Subcommand)]
pub enum Mode {
    Encrypt(Encrypt),
    Decrypt(Decrypt),
    Verify(Verify),
    Version,
}
