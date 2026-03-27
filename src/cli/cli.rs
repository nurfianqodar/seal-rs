use crate::{
    chunk::{OptionalChunk, RequiredChunk},
    cli::{Config, Decrypt, Encrypt, Mode},
    file::{CipherText, Header, PlainText, SealFile},
    result::Result,
};
use clap::Parser;
use rand::{RngExt, distr, rngs};
use std::{fs, io, path};

const CHUNK_SIZE: usize = 1024 * 256;
const ARGON2_VERSION: argon2::Version = argon2::Version::V0x13;

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
            Mode::Encrypt(cfg) => self.encrypt(cfg),

            Mode::Decrypt(cfg) => self.decrypt(cfg),
        }
    }

    fn encrypt(&self, cfg: &Encrypt) -> Result<()> {
        validate_output_path(&cfg.output, cfg.overwrite)?;

        let mut rng = rand::rng();
        let tmp_output = gen_tmp_path(&cfg.output, &mut rng);
        let input_file = fs::File::open_plaintext_file(&cfg.input)?;
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
            cfg.time_cost,
            cfg.memory_cost,
            cfg.parallelism,
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

        fs::rename(&tmp_output, &cfg.output).map_err(|e| {
            _ = fs::remove_file(&tmp_output);
            e
        })?;
        Ok(())
    }

    fn decrypt(&self, cfg: &Decrypt) -> Result<()> {
        validate_output_path(&cfg.output, cfg.overwrite)?;

        let mut rng = rand::rng();
        let tmp_output = gen_tmp_path(&cfg.output, &mut rng);

        let input_file = fs::File::open_ciphertext_file(&cfg.input)?;
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

        fs::rename(&tmp_output, &cfg.output).map_err(|e| {
            _ = fs::remove_file(&tmp_output);
            e
        })?;

        Ok(())
    }
}

// temporary file path
// from /path/to/file.ext -> /path/to/.file.ext<somerandomstring>
fn gen_tmp_path(origin: &str, rng: &mut rngs::ThreadRng) -> path::PathBuf {
    let path = path::Path::new(origin);
    let parent = path.parent().unwrap_or(path::Path::new(""));
    let file_name = path.file_name().unwrap().to_string_lossy();
    let postfix: String = rng
        .sample_iter(&distr::Alphanumeric)
        .take(8)
        .map(char::from)
        .collect();
    let tmp_name = format!(".{}{}", file_name, postfix);
    parent.join(tmp_name)
}

fn validate_output_path(output: &str, overwrite: bool) -> Result<()> {
    let path = path::Path::new(output);
    if path.try_exists()? {
        if !overwrite {
            return Err(io::Error::new(io::ErrorKind::AlreadyExists, "already exists").into());
        }
        let meta = fs::metadata(path)?;
        if !meta.is_file() {
            return Err(io::Error::new(io::ErrorKind::IsADirectory, "not a file").into());
        }
    }
    Ok(())
}
