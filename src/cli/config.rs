#[derive(Debug, clap::Parser)]
pub struct Config {
    #[command(subcommand)]
    pub mode: Mode,
}

#[derive(Debug, Clone, clap::Subcommand)]
pub enum Mode {
    Encrypt {
        #[arg(short, long, help = "path to input file")]
        input: String,

        #[arg(short, long, help = "path to output file")]
        output: String,

        #[arg(
            short,
            default_value_t = 65536,
            help = "memory cost (KiB) [default 65536 KiB]"
        )]
        m_cost: u32,

        #[arg(
            short,
            default_value_t = 3,
            help = "number of iterations (time cost) [default 3]"
        )]
        t_cost: u32,

        #[arg(
            short,
            default_value_t = 2,
            help = "number of threads (parallelism) [default 2]"
        )]
        p_cost: u32,

        #[arg(
            long,
            default_value_t = false,
            help = "overwrite output file if exists"
        )]
        overwrite: bool,
    },
    Decrypt {
        #[arg(short)]
        input: String,
        #[arg(short)]
        output: String,
        #[arg(
            long,
            default_value_t = false,
            help = "overwrite output file if exists"
        )]
        overwrite: bool,
    },
}
