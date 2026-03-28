use crate::{error::Error, result::Result};
use rand::{RngExt, distr};
use std::{fs, path};

pub fn validate_output_path(output: &str, overwrite: bool) -> Result<()> {
    let path = path::Path::new(output);
    if path.try_exists()? {
        if !overwrite {
            return Err(Error::AlreadyExists);
        }
        let meta = fs::metadata(path)?;
        if !meta.is_file() {
            return Err(Error::NotAFile);
        }
    }
    Ok(())
}

// temporary file path
// from /path/to/file.ext -> /path/to/.file.ext<somerandomstring>
pub fn gen_tmp_path(origin: &str) -> path::PathBuf {
    let rng = rand::rng();
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
