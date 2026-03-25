use std::{fs, io};

use clap::Parser;
use rand::{RngExt, distr, rngs};

use crate::{
    chunk::{OptionalChunk, RequiredChunk},
    cli::{Config, Mode, guard::ask_password},
    file::{CipherFileReader, CipherText, FileWriter, Header, PlainFileReader, PlainText},
    result::Result,
};

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
        let mut actual_output = output.to_string();
        let mut rng: rngs::StdRng = rand::make_rng();

        if input == output {
            let postfix: String = (&mut rng)
                .sample_iter(&distr::Alphanumeric)
                .take(10)
                .map(char::from)
                .collect();
            actual_output = format!("{}.{}", actual_output, postfix);
        }

        // ensure file configured successfuly before go to next processes
        let mut ifile = PlainFileReader::open(input)?;
        let mut ofile = FileWriter::create(&actual_output, overwrite)?;

        let password = ask_password()?;

        let mut reader = ifile.reader();
        let mut writer = ofile.writer();

        let header = Header::new(&mut rng, argon2::Version::V0x13, t_cost, m_cost, p_cost);
        header.write_to(&mut writer)?;

        let mut cipher = header.gen_cipher(&password)?;

        while let Some(plaintext) = PlainText::<{ 1024 * 256 }>::read_from(&mut reader)? {
            let ciphertext = plaintext.encrypt(&mut rng, &header, &mut cipher)?;
            ciphertext.write_to(&mut writer)?;
        }
        if input == output {
            fs::rename(&actual_output, output)?;
        }

        Ok(())
    }

    fn decrypt(&self, input: &str, output: &str, overwrite: bool) -> Result<()> {
        let mut actual_output = output.to_string();
        let mut rng: rngs::StdRng = rand::make_rng();
        if input == output {
            let postfix: String = (&mut rng)
                .sample_iter(&distr::Alphanumeric)
                .take(10)
                .map(char::from)
                .collect();
            actual_output = format!("{}.{}", actual_output, postfix);
        } else {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "output file already exists. use --overwrite instead",
            )
            .into());
        }
        // ensure file configured successfuly before go to next processes
        let mut ifile = CipherFileReader::open(input)?;
        let mut ofile = FileWriter::create(&actual_output, overwrite)?;

        let password = ask_password()?;

        let mut reader = ifile.reader();
        let header = Header::read_from(&mut reader)?;
        let mut cipher = header.gen_cipher(&password)?;

        let mut writer = ofile.writer();

        while let Some(ciphertext) = CipherText::<{ 1024 * 256 }>::read_from(&mut reader)? {
            let plaintext = ciphertext.decrypt(&header, &mut cipher)?;
            plaintext.write_to(&mut writer)?;
        }

        if input == output {
            fs::rename(&actual_output, output)?;
        }

        Ok(())
    }
}
