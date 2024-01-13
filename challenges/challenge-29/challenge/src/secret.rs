mod rng;
mod constants;

use groestl::{Digest, Groestl512};

use rng::Rng;

fn demangle(device: u64) -> u64 {
    (((((device >> 10) - 0xdead) << 4) | 0xc001c0de) ^ 0xbadc0ffee) - 0x195c98dc4ba0346
}

fn firmware() {
    println!("======= Firmware =======");
     let seed = u64::from_le_bytes([242, 39, 120, 8, 197, 92, 215, 51]);
     let data = [
        [31, 161, 225, 35, 83, 185, 150, 95],
        [24, 15, 92, 157, 131, 137, 101, 156],
        [245, 157, 104, 226, 66, 227, 14, 21],
        [193, 227, 36, 190, 203, 79, 141, 106],
        [24, 51, 17, 135, 251, 2, 25, 23],
        [1, 3, 102, 246, 69, 254, 205, 166],
        [161, 143, 114, 120, 70, 164, 188, 79]
     ];

    let mut rng = Rng::new(seed);
    println!("{seed:#x}");
    let mut magic = 0;

    for x in 0..7 {
        let b = u64::from_le_bytes(data[x]);
        let key = constants::KEYS[rng.rand_u8() as usize];
        magic ^= b ^ key;
        println!("{b:#x} {key:#x} {magic:#x}")
    }
}

fn periphery() {
    println!("======= Periphery =======");
    let seed = demangle(u64::from_le_bytes(*b"firmware"));
    let mut rng = Rng::new(seed);
    let mut data = 0;

    for _ in 0..16 {
        data ^= rng.rand();
    }

    let mut hasher = Groestl512::default();
    hasher.update(data.to_le_bytes());
    let hash = hasher.finalize();

    println!("Len {}", hash.len());
    for x in 0..8 {
        println!("{:?}", &hash[x*8..(x+1)*8]);
    }
}

fn main() {
    periphery();
    firmware();
}
