mod action;
mod config;
mod util;

use crate::{
    cli::{Config, Mode, action::Action},
    core::VERSION_STRING,
    result::Result,
};
use clap::Parser;
pub use config::*;

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
            Mode::Encrypt(encrypt) => {
                encrypt.run()?;
                println!("encrypt success");
                Ok(())
            }
            Mode::Decrypt(decrypt) => {
                decrypt.run()?;
                println!("decrypt success");
                Ok(())
            }
            Mode::Verify(verify) => {
                verify.run()?;
                println!("verify success");
                Ok(())
            }
            Mode::Version => {
                println!("seal v{}", VERSION_STRING);
                Ok(())
            }
        }
    }
}

