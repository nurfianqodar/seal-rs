use std::{fs, io};

use crate::{
    cli::util::{gen_tmp_path, validate_output_path},
    core::{decrypt, encrypt},
    file::SealFile,
    result::Result,
};

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
        long,
        default_value_t = false,
        help = "overwrite output file if exists"
    )]
    overwrite: bool,
}

impl Action for Encrypt {
    fn run(&self) -> Result<()> {
        validate_output_path(&self.output, self.overwrite)?;
        let password = rpassword::prompt_password("password: ")?;
        let tmp_output = gen_tmp_path(&self.output);
        let mut reader = io::BufReader::new(fs::File::open_plaintext_file(&self.input)?);
        let mut writer = io::BufWriter::new(fs::File::create_out_file(&tmp_output)?);
        encrypt(&mut reader, &mut writer, &password).inspect_err(|_| {
            _ = fs::remove_file(&tmp_output);
        })?;
        fs::rename(&tmp_output, &self.output).inspect_err(|_| {
            _ = fs::remove_file(&tmp_output);
        })?;
        Ok(())
    }
}

#[derive(Debug, Clone, clap::Args)]
pub struct Decrypt {
    #[arg(short, long, help = "path to input file")]
    input: String,
    #[arg(short, long, help = "path to output file")]
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
        let password = rpassword::prompt_password("password: ")?;
        let tmp_output = gen_tmp_path(&self.output);
        let mut reader = io::BufReader::new(fs::File::open_ciphertext_file(&self.input)?);
        let mut writer = io::BufWriter::new(fs::File::create_out_file(&tmp_output)?);
        decrypt(&mut reader, &mut writer, &password).inspect_err(|_| {
            _ = fs::remove_file(&tmp_output);
        })?;
        fs::rename(&tmp_output, &self.output).inspect_err(|_| {
            _ = fs::remove_file(&tmp_output);
        })?;
        Ok(())
    }
}
