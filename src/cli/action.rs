use std::{fs, io};

use crate::{
    chunk::{OptionalChunk, RequiredChunk},
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

impl Action for Encrypt {
    fn run(&self) -> Result<()> {
        validate_output_path(&self.output, self.overwrite)?;

        let mut rng = rand::rng();
        let tmp_output = gen_tmp_path(&self.output, &mut rng);
        let input_file = fs::File::open_plaintext_file(&self.input)?;
        let output_file = fs::File::create_out_file(&tmp_output)?;
        let mut reader = io::BufReader::new(input_file);
        let mut writer = io::BufWriter::new(output_file);

        let password = rpassword::prompt_password("password: ").map_err(|e| {
            _ = fs::remove_file(&tmp_output);
            e
        })?;

        let header = Header::new(
            &mut rng,
            ARGON2_VERSION,
            self.time_cost,
            self.memory_cost,
            self.parallelism,
        );

        header.write_to(&mut writer).map_err(|e| {
            _ = fs::remove_file(&tmp_output);
            e
        })?;

        let mut cipher = header.gen_cipher(&password).map_err(|e| {
            _ = fs::remove_file(&tmp_output);
            e
        })?;

        while let Some(plaintext) =
            PlainText::<CHUNK_SIZE>::read_from(&mut reader).map_err(|e| {
                _ = fs::remove_file(&tmp_output);
                e
            })?
        {
            let ciphertext = plaintext
                .encrypt(&mut rng, &header, &mut cipher)
                .map_err(|e| {
                    _ = fs::remove_file(&tmp_output);
                    e
                })?;

            ciphertext.write_to(&mut writer).map_err(|e| {
                _ = fs::remove_file(&tmp_output);
                e
            })?;
        }

        fs::rename(&tmp_output, &self.output).map_err(|e| {
            _ = fs::remove_file(&tmp_output);
            e
        })?;
        Ok(())
    }
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

impl Action for Decrypt {
    fn run(&self) -> Result<()> {
        validate_output_path(&self.output, self.overwrite)?;

        let mut rng = rand::rng();
        let tmp_output = gen_tmp_path(&self.output, &mut rng);

        let input_file = fs::File::open_ciphertext_file(&self.input)?;
        let output_file = fs::File::create_out_file(&tmp_output)?;

        let mut reader = io::BufReader::new(input_file);
        let mut writer = io::BufWriter::new(output_file);

        let password = rpassword::prompt_password("password: ").map_err(|e| {
            _ = fs::remove_file(&tmp_output);
            e
        })?;

        let header = Header::read_from(&mut reader).map_err(|e| {
            _ = fs::remove_file(&tmp_output);
            e
        })?;

        let mut cipher = header.gen_cipher(&password).map_err(|e| {
            _ = fs::remove_file(&tmp_output);
            e
        })?;

        while let Some(ciphertext) =
            CipherText::<CHUNK_SIZE>::read_from(&mut reader).map_err(|e| {
                _ = fs::remove_file(&tmp_output);
                e
            })?
        {
            let plaintext = ciphertext.decrypt(&header, &mut cipher).map_err(|e| {
                _ = fs::remove_file(&tmp_output);
                e
            })?;
            plaintext.write_to(&mut writer).map_err(|e| {
                _ = fs::remove_file(&tmp_output);
                e
            })?;
        }

        fs::rename(&tmp_output, &self.output).map_err(|e| {
            _ = fs::remove_file(&tmp_output);
            e
        })?;

        Ok(())
    }
}
