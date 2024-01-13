use std::io::{Read, Write};
use rand::prelude::*;
use rand_chacha::ChaCha8Rng;

fn main() {
    let mut buf = Vec::new();
    std::io::stdin().read_to_end(&mut buf).unwrap();
    let num_buf: [u8; 8] = buf.try_into().unwrap();
    let seed = u64::from_le_bytes(num_buf);

    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let mut buffer = [0u8; 32];
    rng.fill_bytes(&mut buffer);
    std::io::stdout().write(&buffer).unwrap();
}
