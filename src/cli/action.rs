use zeroize::Zeroize;

use crate::cli::util::{gen_tmp_path, validate_output_path};
use crate::core::{decrypt, encrypt};
use crate::error::Error;
use crate::file::SealFile;
use crate::result::Result;
use std::io::Write;
use std::{fs, io};

pub trait Action {
    fn run(&self) -> Result<()>;
}

#[derive(Debug, Clone, clap::Args, zeroize::ZeroizeOnDrop)]
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
    #[arg(long, short)]
    password: Option<String>,
}

impl Action for Encrypt {
    fn run(&self) -> Result<()> {
        validate_output_path(&self.output, self.overwrite)?;
        let mut password;
        if let Some(pwd) = &self.password {
            password = pwd.clone();
        } else {
            password = rpassword::prompt_password("password: ")?;
            let mut retype_password = rpassword::prompt_password("retype password: ")?;
            if password != retype_password {
                password.zeroize();
                retype_password.zeroize();
                return Err(Error::PasswordNotMatch)?;
            }
            retype_password.zeroize();
        }
        if password.is_empty() {
            return Err(Error::EmptyPassword);
        }
        let tmp_output = gen_tmp_path(&self.output);
        let mut reader = fs::File::open_plaintext_reader(&self.input).inspect_err(|_| {
            password.zeroize();
        })?;
        let mut writer = fs::File::create_out_writer(&tmp_output).inspect_err(|_| {
            password.zeroize();
        })?;
        encrypt(&mut reader, &mut writer, &password).inspect_err(|_| {
            password.zeroize();
            _ = fs::remove_file(&tmp_output);
        })?;
        writer.flush()?;
        fs::rename(&tmp_output, &self.output).inspect_err(|_| {
            password.zeroize();
            _ = fs::remove_file(&tmp_output);
        })?;
        password.zeroize();
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
    #[arg(long, short)]
    password: Option<String>,
}

impl Action for Decrypt {
    fn run(&self) -> Result<()> {
        validate_output_path(&self.output, self.overwrite)?;
        let mut password;
        if let Some(pwd) = &self.password {
            password = pwd.clone();
        } else {
            password = rpassword::prompt_password("password: ")?;
            let mut retype_password = rpassword::prompt_password("retype password: ")?;
            if password != retype_password {
                password.zeroize();
                retype_password.zeroize();
                return Err(Error::PasswordNotMatch)?;
            }
            retype_password.zeroize();
        }
        if password.is_empty() {
            return Err(Error::EmptyPassword);
        }
        let tmp_output = gen_tmp_path(&self.output);
        let mut reader = fs::File::open_ciphertext_reader(&self.input).inspect_err(|_| {
            password.zeroize();
        })?;
        let mut writer = fs::File::create_out_writer(&tmp_output).inspect_err(|_| {
            password.zeroize();
        })?;
        decrypt(&mut reader, &mut writer, &password).inspect_err(|_| {
            _ = fs::remove_file(&tmp_output);
        })?;
        password.zeroize();
        writer.flush()?;
        fs::rename(&tmp_output, &self.output).inspect_err(|_| {
            _ = fs::remove_file(&tmp_output);
        })?;
        Ok(())
    }
}

#[derive(Debug, Clone, clap::Args)]
pub struct Verify {
    #[arg(short, long, help = "path to input file")]
    input: String,
    #[arg(short, long)]
    password: Option<String>,
}

impl Action for Verify {
    fn run(&self) -> Result<()> {
        let mut password;
        if let Some(pwd) = &self.password {
            password = pwd.clone();
        } else {
            password = rpassword::prompt_password("password: ")?;
            let mut retype_password = rpassword::prompt_password("retype password: ")?;
            if password != retype_password {
                password.zeroize();
                retype_password.zeroize();
                return Err(Error::PasswordNotMatch)?;
            }
            retype_password.zeroize();
        }
        if password.is_empty() {
            return Err(Error::EmptyPassword);
        }

        let mut reader = fs::File::open_ciphertext_reader(&self.input).inspect_err(|_| {
            password.zeroize();
        })?;
        let mut writer = io::sink();
        decrypt(&mut reader, &mut writer, &password).map_err(|_| {
            password.zeroize();
            Error::VerificationFailed
        })?;
        password.zeroize();
        Ok(())
    }
}
