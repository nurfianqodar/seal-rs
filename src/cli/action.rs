use std::{fs, io};

use crate::{
    file::{OptionalChunk, RequiredChunk},
    cli::util::{gen_tmp_path, validate_output_path},
    file::{CipherText, Header, PlainText, SealFile},
    result::Result,
};

const CHUNK_SIZE: usize = 1024 * 256;
const ARGON2_VERSION: argon2::Version = argon2::Version::V0x13;

pub trait Action {
    fn run(&self) -> Result<()>;
}

#[derive(Debug, Clone, clap::Args)]
pub struct Encrypt {
    #[arg(short, long, help = "path to input file")]
    input: String,
    #[arg(short, long, help = "path to output file")]
    output: String,
    #[arg(
        short,
        default_value_t = 65536,
        help = "memory cost (KiB) [default 65536 KiB]"
    )]
    memory_cost: u32,
    #[arg(
        short,
        default_value_t = 3,
        help = "number of iterations (time cost) [default 3]"
    )]
    time_cost: u32,
    #[arg(
        short,
        default_value_t = 2,
        help = "number of threads (parallelism) [default 2]"
    )]
    parallelism: u32,
    #[arg(
        long,
        default_value_t = false,
        help = "overwrite output file if exists"
    )]
    overwrite: bool,
}

impl Action for Encrypt {
    fn run(&self) -> Result<()> {
        validate_output_path(&self.output, self.overwrite)?;

        let mut rng = rand::rng();
        let tmp_output = gen_tmp_path(&self.output, &mut rng);
        let input_file = fs::File::open_plaintext_file(&self.input)?;
        let output_file = fs::File::create_out_file(&tmp_output)?;
        let mut reader = io::BufReader::new(input_file);
        let mut writer = io::BufWriter::new(output_file);

        self.encrypt(&mut rng, &mut reader, &mut writer)
            .inspect_err(|_| {
                _ = fs::remove_file(&tmp_output);
            })?;

        fs::rename(&tmp_output, &self.output).inspect_err(|_| {
            _ = fs::remove_file(&tmp_output);
        })?;
        Ok(())
    }
}

impl Encrypt {
    fn encrypt<R>(
        &self,
        rng: &mut R,
        reader: &mut io::BufReader<fs::File>,
        writer: &mut io::BufWriter<fs::File>,
    ) -> Result<()>
    where
        R: rand::Rng,
    {
        let password = rpassword::prompt_password("password: ")?;
        let header = Header::new(
            rng,
            ARGON2_VERSION,
            self.time_cost,
            self.memory_cost,
            self.parallelism,
        );
        header.write_to(writer)?;
        let mut cipher = header.gen_cipher(&password)?;
        while let Some(plaintext) = PlainText::<CHUNK_SIZE>::read_from(reader)? {
            let ciphertext = plaintext.encrypt(rng, &header, &mut cipher)?;
            ciphertext.write_to(writer)?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone, clap::Args)]
pub struct Decrypt {
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
}

impl Action for Decrypt {
    fn run(&self) -> Result<()> {
        validate_output_path(&self.output, self.overwrite)?;

        let mut rng = rand::rng();
        let tmp_output = gen_tmp_path(&self.output, &mut rng);

        let input_file = fs::File::open_ciphertext_file(&self.input)?;
        let output_file = fs::File::create_out_file(&tmp_output)?;

        let mut reader = io::BufReader::new(input_file);
        let mut writer = io::BufWriter::new(output_file);

        self.decrypt(&mut reader, &mut writer).inspect_err(|_| {
            _ = fs::remove_file(&tmp_output);
        })?;

        fs::rename(&tmp_output, &self.output).inspect_err(|_| {
            _ = fs::remove_file(&tmp_output);
        })?;

        Ok(())
    }
}

impl Decrypt {
    fn decrypt(
        &self,
        reader: &mut io::BufReader<fs::File>,
        writer: &mut io::BufWriter<fs::File>,
    ) -> Result<()> {
        let password = rpassword::prompt_password("password: ")?;
        let header = Header::read_from(reader)?;
        let mut cipher = header.gen_cipher(&password)?;
        while let Some(ciphertext) = CipherText::<CHUNK_SIZE>::read_from(reader)? {
            let plaintext = ciphertext.decrypt(&header, &mut cipher)?;
            plaintext.write_to(writer)?;
        }
        Ok(())
    }
}
