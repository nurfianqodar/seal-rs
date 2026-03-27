use std::{fs, io, path};

use crate::{
    chunk::{OptionalChunk, RequiredChunk},
    cli::{Config, Mode, guard::ask_password},
    file::{CipherText, Header, PlainText, SealFile},
    result::Result,
};
use clap::Parser;
use rand::{RngExt, distr, rngs};

const CHUNK_SIZE: usize = 1024 * 256;
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
            Mode::Encrypt {
                input,
                output,
                m_cost,
                t_cost,
                p_cost,
                overwrite,
            } => self.encrypt(&input, &output, *m_cost, *t_cost, *p_cost, *overwrite),

            Mode::Decrypt {
                input,
                output,
                overwrite,
            } => self.decrypt(&input, &output, *overwrite),
        }
    }

    fn encrypt(
        &self,
        input: &str,
        output: &str,
        m_cost: u32,
        t_cost: u32,
        p_cost: u32,
        overwrite: bool,
    ) -> Result<()> {
        validate_output_path(output, overwrite)?;

        let mut rng = rand::rng();
        let tmp_output = gen_tmp_path(output, &mut rng);
        let input_file = fs::File::open_plaintext_file(input)?;
        let output_file = fs::File::create_out_file(&tmp_output)?;
        let mut reader = io::BufReader::new(input_file);
        let mut writer = io::BufWriter::new(output_file);

        let password = ask_password().map_err(|e| {
            _ = fs::remove_file(&tmp_output);
            e
        })?;

        const ARGON2_VERSION: argon2::Version = argon2::Version::V0x13;
        let header = Header::new(&mut rng, ARGON2_VERSION, t_cost, m_cost, p_cost);

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

        fs::rename(&tmp_output, output).map_err(|e| {
            _ = fs::remove_file(&tmp_output);
            e
        })?;
        Ok(())
    }

    fn decrypt(&self, input: &str, output: &str, overwrite: bool) -> Result<()> {
        let mut rng = rand::rng();
        validate_output_path(output, overwrite)?;
        let tmp_output = gen_tmp_path(output, &mut rng);

        let input_file = fs::File::open_ciphertext_file(input)?;
        let output_file = fs::File::create_out_file(&tmp_output)?;
        let mut reader = io::BufReader::new(input_file);
        let mut writer = io::BufWriter::new(output_file);

        let password = ask_password().map_err(|e| {
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

        fs::rename(&tmp_output, output).map_err(|e| {
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
    if path.exists() {
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
