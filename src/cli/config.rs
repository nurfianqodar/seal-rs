use crate::cli::action::{Decrypt, Encrypt};

#[derive(Debug, clap::Parser)]
pub struct Config {
    #[command(subcommand)]
    pub mode: Mode,
}

#[derive(Debug, Clone, clap::Subcommand)]
pub enum Mode {
    Encrypt(Encrypt),
    Decrypt(Decrypt),
}
