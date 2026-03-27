use crate::cli::Cli;

mod chunk;
mod cli;
mod error;
mod ext;
mod file;
mod result;

fn main() {
    let cli = Cli::new();
    if let Err(e) = cli.run() {
        println!("{}", e);
    }
}
