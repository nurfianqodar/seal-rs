use crate::{cli::Cli, result::Result};

mod chunk;
mod cli;
mod error;
mod ext;
mod file;
mod result;

fn main() -> Result<()> {
    let cli = Cli::new();
    cli.run()?;
    Ok(())
}
