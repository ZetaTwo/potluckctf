#![feature(start, exposed_provenance)]
#![allow(non_snake_case)]
#![no_std]

mod rng;
mod rehost;
mod constants;
mod intrinsics;

use core::panic::PanicInfo;

use rng::Rng;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

// firmware
#[start]
fn main(_argc: isize, _argv: *const *const u8) -> isize {
    rehost::send_data(b"letsa go");

    let init = rehost::recv_data();
    if &init != b"herewego" {
        return -1;
    }

    rehost::send_data(b"firmware");
    let seed: [u8; 8] = rehost::recv_data();
    let mut rng = Rng::new(u64::from_le_bytes(seed));

    let mut magic = 0;

    for _ in 0..7 {
        magic ^= u64::from_le_bytes(rehost::recv_data()) ^ constants::KEYS[rng.rand_u8() as usize];
    }

    if magic == 0x93273f7fd2ec9c1e {
        rehost::send_flag();
        return 0;
    }

    -1
}
