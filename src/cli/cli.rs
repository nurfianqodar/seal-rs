use crate::{
    cli::{Config, Mode, action::Action},
    result::Result,
};
use clap::Parser;

pub struct Cli {
    config: Config,
}

impl Cli {
    pub fn new() -> Cli {
        let config = Config::parse();
        Self { config }
    }

    pub fn run(&self) -> Result<()> {
        match &self.config.mode {
            Mode::Encrypt(encrypt) => encrypt.run(),
            Mode::Decrypt(decrypt) => decrypt.run(),
        }
    }
}
