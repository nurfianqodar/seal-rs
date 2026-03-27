pub const ID_LEN: usize = 4;

pub fn new_id<R>(rng: &mut R) -> [u8; ID_LEN]
where
    R: rand::Rng,
{
    let mut id = [0u8; ID_LEN];
    rng.fill_bytes(&mut id);
    id
}
