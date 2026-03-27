use crate::cli::Cli;

mod cli;
mod error;
mod file;
mod result;

fn main() {
    let cli = Cli::new();
    if let Err(e) = cli.run() {
        println!("{}", e);
    }
}
