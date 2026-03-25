use crate::result::Result;

pub fn ask_password() -> Result<String> {
    let password = rpassword::prompt_password("password: ")?;
    Ok(password)
}
