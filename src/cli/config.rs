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

#[derive(Debug, Clone, clap::Args)]
pub struct Encrypt {
    #[arg(short, long, help = "path to input file")]
    pub input: String,
    #[arg(short, long, help = "path to output file")]
    pub output: String,
    #[arg(
        short,
        default_value_t = 65536,
        help = "memory cost (KiB) [default 65536 KiB]"
    )]
    pub memory_cost: u32,
    #[arg(
        short,
        default_value_t = 3,
        help = "number of iterations (time cost) [default 3]"
    )]
    pub time_cost: u32,
    #[arg(
        short,
        default_value_t = 2,
        help = "number of threads (parallelism) [default 2]"
    )]
    pub parallelism: u32,
    #[arg(
        long,
        default_value_t = false,
        help = "overwrite output file if exists"
    )]
    pub overwrite: bool,
}

#[derive(Debug, Clone, clap::Args)]
pub struct Decrypt {
    #[arg(short)]
    pub input: String,
    #[arg(short)]
    pub output: String,
    #[arg(
        long,
        default_value_t = false,
        help = "overwrite output file if exists"
    )]
    pub overwrite: bool,
}
