use crate::core::{FILE_ID_LEN, MAGIC, MAGIC_LEN, RequiredChunk, SALT_LEN, VERSION, VERSION_LEN};
use crate::result::Result;
use aes_gcm::KeyInit;
use rand::Rng;

#[derive(Debug, PartialEq, Eq, zeroize::ZeroizeOnDrop, zeroize::Zeroize)]
pub struct Header {
    magic: [u8; MAGIC_LEN],
    version: [u8; VERSION_LEN],
    file_id: [u8; FILE_ID_LEN],
    #[zeroize(skip)]
    argon2_version: argon2::Version,
    salt: [u8; SALT_LEN],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
}

impl RequiredChunk for Header {
    fn read_from<R>(reader: &mut R) -> Result<Self>
    where
        R: std::io::Read,
        Self: Sized,
    {
        // order:
        // magic,version,file_id,argon2_version,salt,m_cost,t_cost,p_cost
        let mut magic: [u8; MAGIC_LEN] = [0; MAGIC_LEN];
        reader.read_exact(&mut magic)?;
        let mut version: [u8; VERSION_LEN] = [0; VERSION_LEN];
        reader.read_exact(&mut version)?;
        let mut file_id: [u8; FILE_ID_LEN] = [0; FILE_ID_LEN];
        reader.read_exact(&mut file_id)?;
        let argon2_version = u32::read_from(reader)?;
        let mut salt: [u8; SALT_LEN] = [0; SALT_LEN];
        reader.read_exact(&mut salt)?;
        let m_cost = u32::read_from(reader)?;
        let t_cost = u32::read_from(reader)?;
        let p_cost = u32::read_from(reader)?;

        let header = Self {
            magic,
            version,
            file_id,
            argon2_version: argon2_version.try_into()?,
            salt,
            m_cost,
            t_cost,
            p_cost,
        };
        Ok(header)
    }

    fn write_to<W>(&self, writer: &mut W) -> Result<()>
    where
        W: std::io::Write,
        Self: Sized,
    {
        // order:
        // magic,version,file_id,argon2_version,salt,m_cost,t_cost,p_cost
        writer.write_all(&self.magic)?;
        writer.write_all(&self.version)?;
        writer.write_all(&self.file_id)?;
        (self.argon2_version as u32).write_to(writer)?;
        writer.write_all(&self.salt)?;
        self.m_cost.write_to(writer)?;
        self.t_cost.write_to(writer)?;
        self.p_cost.write_to(writer)?;
        Ok(())
    }
}

impl Header {
    pub fn new(argon2_version: argon2::Version, t_cost: u32, m_cost: u32, p_cost: u32) -> Self {
        let mut rng = rand::rng();
        let mut file_id = [0u8; FILE_ID_LEN];
        rng.fill_bytes(&mut file_id);

        let mut salt = [0u8; SALT_LEN];
        rng.fill_bytes(&mut salt);

        Self {
            magic: MAGIC,
            version: VERSION,
            file_id,
            argon2_version,
            salt,
            t_cost,
            m_cost,
            p_cost,
        }
    }

    pub fn gen_cipher(&self, password: &str) -> Result<aes_gcm::Aes256Gcm> {
        let params = argon2::Params::new(self.m_cost, self.t_cost, self.p_cost, Some(32))?;
        let a2id = argon2::Argon2::new(argon2::Algorithm::Argon2id, self.argon2_version, params);
        let mut key = [0u8; 32];
        a2id.hash_password_into(password.as_bytes(), &self.salt, &mut key)?;
        let cipher = aes_gcm::Aes256Gcm::new((&key).into());
        Ok(cipher)
    }

    pub fn gen_nonce(&self, end: [u8; 4]) -> [u8; FILE_ID_LEN + 4] {
        let mut nonce = [0u8; FILE_ID_LEN + 4];
        nonce[0..FILE_ID_LEN].copy_from_slice(&self.file_id);
        nonce[FILE_ID_LEN..].copy_from_slice(&end);
        nonce
    }
}

#[cfg(test)]
mod tests {
    use crate::core::{RequiredChunk, header::Header};
    use crate::result::Result;
    use std::fs;

    fn create_tmp_file(name: &str) -> fs::File {
        let path = std::env::temp_dir().join(name);
        let f = fs::File::create(&path).unwrap();
        f
    }

    fn open_tmp_file(name: &str) -> fs::File {
        let path = std::env::temp_dir().join(name);
        let f = fs::File::open(&path).unwrap();
        f
    }

    #[test]
    fn write_read_header_consistency() -> Result<()> {
        let fname = "header.bin";

        let mut f = create_tmp_file(fname);
        let header1 = Header::new(argon2::Version::V0x13, 3, 1024 * 64, 2);
        header1.write_to(&mut f)?;

        let mut f = open_tmp_file(fname);
        let header2 = Header::read_from(&mut f)?;

        assert_eq!(header1, header2);
        Ok(())
    }
}
