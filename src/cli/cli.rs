use std::io::{self, Write};

use clap::Parser;
use rand::rngs;

use crate::{
    chunk::{OptionalChunk, RequiredChunk},
    cli::{Config, Mode},
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
        let mut rng: rngs::StdRng = rand::make_rng();
        let header = Header::new(&mut rng, argon2::Version::V0x13, t_cost, m_cost, p_cost);
        let password = ask_password()?;
        let mut cipher = header.gen_cipher(&password)?;
        let mut ifile = PlainFileReader::open(input)?;
        let mut ofile = FileWriter::create(output, overwrite)?;

        let mut reader = ifile.reader();
        let mut writer = ofile.writer();

        header.write_to(&mut writer)?;

        while let Some(plaintext) = PlainText::<{ 1024 * 256 }>::read_from(&mut reader)? {
            let ciphertext = plaintext.encrypt(&mut rng, &header, &mut cipher)?;
            ciphertext.write_to(&mut writer)?;
        }

        Ok(())
    }

    fn decrypt(&self, input: &str, output: &str, overwrite: bool) -> Result<()> {
        let password = ask_password()?;

        let mut ifile = CipherFileReader::open(input)?;

        let mut reader = ifile.reader();
        let header = Header::read_from(&mut reader)?;
        let mut cipher = header.gen_cipher(&password)?;

        let mut ofile = FileWriter::create(output, overwrite)?;
        let mut writer = ofile.writer();

        while let Some(ciphertext) = CipherText::<{ 1024 * 256 }>::read_from(&mut reader)? {
            let plaintext = ciphertext.decrypt(&header, &mut cipher)?;
            plaintext.write_to(&mut writer)?;
        }

        Ok(())
    }
}

fn ask_password() -> Result<String> {
    let mut buf = String::new();
    print!("Input password: ");
    io::stdout().flush()?;
    io::stdin().read_line(&mut buf)?;
    Ok(buf)
}
