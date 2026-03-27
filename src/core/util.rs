use rand::Rng;

pub const ID_LEN: usize = 4;

pub fn new_id() -> [u8; ID_LEN] {
    let mut rng = rand::rng();
    let mut id = [0u8; ID_LEN];
    rng.fill_bytes(&mut id);
    id
}
