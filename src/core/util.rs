use rand::Rng;

pub const ID_LEN: usize = 4;

pub fn new_id() -> [u8; ID_LEN] {
    let mut rng = rand::rng();
    let mut id = [0u8; ID_LEN];
    rng.fill_bytes(&mut id);
    id
}

#[cfg(test)]
mod tests {
    use crate::core::util::new_id;

    #[test]
    fn id_is_random() {
        let id1 = new_id();
        let id2 = new_id();
        assert_ne!(id1, id2);
    }
}
