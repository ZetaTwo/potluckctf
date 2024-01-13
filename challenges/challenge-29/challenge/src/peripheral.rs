#![feature(start, exposed_provenance)]
#![allow(non_snake_case)]
#![no_std]

mod rng;
mod rehost;
mod constants;
mod intrinsics;

use core::panic::PanicInfo;

use groestl::{Digest, Groestl512};

use rng::Rng;

fn demangle(device: u64) -> u64 {
    (((((device >> 10) - 0xdead) << 4) | 0xc001c0de) ^ 0xbadc0ffee) - 0x195c98dc4ba0346
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

// periphery
#[start]
fn main(_argc: isize, _argv: *const *const u8) -> isize {
    let initial: [u8; 8] = rehost::recv_data();
    if &initial != b"letsa go" {
        return -1;
    }
    rehost::send_data(b"herewego");

    let seed = demangle(u64::from_le_bytes(rehost::recv_data()));
    let mut rng = Rng::new(seed);

    // use hash as seed for rng in firmware -> use rng to check data from periph
    let mut data = 0;

    for _ in 0..16 {
        data ^= rng.rand();
    }

    let mut hasher = Groestl512::default();
    hasher.update(data.to_le_bytes());
    let hash = hasher.finalize();

    for x in 0..8 {
        rehost::send_data(&hash[x*8..(x+1)*8]);
    }

    let _ = rehost::recv_flag();
    0
}
