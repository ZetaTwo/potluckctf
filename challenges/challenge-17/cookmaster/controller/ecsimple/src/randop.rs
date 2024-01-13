use crate::fileop::*;
#[allow(unused_imports)]
use crate::logger::*;
use crate::*;
use num_bigint::{BigInt, Sign};
use num_traits::{one, zero};
use rand;
use std::error::Error;
//use rand_core::CryptoRng;
use lazy_static::lazy_static;
use rand_chacha::ChaCha8Rng;
use rand_core::{RngCore, SeedableRng};
use std::env;
use tokio::sync::Mutex;

pub(crate) fn get_max_bits(bn: &BigInt) -> i64 {
    let mut retv: i64 = -1;
    let mut idx: i64 = 0;
    let zv: BigInt = zero();
    let mut cv: BigInt = one();

    while bn >= &cv {
        if (&cv & bn) != zv {
            /*for expand*/
            retv = idx + 1;
        }
        idx += 1;
        cv <<= 1;
    }
    return retv;
}

pub struct RandOps {
    gencore: Option<ChaCha8Rng>,
    filerand: Option<RandFile>,
    begen: bool,
    pos: usize,
}

impl RandOps {
    pub fn new(fname: Option<String>) -> Result<Self, Box<dyn Error>> {
        let mut retv = RandOps {
            gencore: None,
            filerand: None,
            begen: true,
            pos: 0,
        };
        if fname.is_none() {
            let seed = rand::thread_rng().next_u64();
            retv.gencore = Some(ChaCha8Rng::seed_from_u64(seed));
        } else {
            retv.filerand = Some(RandFile::new(fname.as_ref().unwrap())?);
            retv.begen = false;
        }
        Ok(retv)
    }

    pub fn get_bytes(&mut self, num: usize) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut buf: Vec<u8> = Vec::new();
        for _ in 0..num {
            buf.push(0x0);
        }
        if self.begen {
            self.gencore.as_mut().unwrap().try_fill_bytes(&mut buf)?;
        } else {
            self.filerand.as_mut().unwrap().try_fill_bytes(&mut buf)?;
        }
        //ecsimple_log_trace!("get pos [0x{:x}] size [0x{:x}]",self.pos,num);
        self.pos += num;
        Ok(buf)
    }
}

impl rand_core::CryptoRng for RandOps {}

impl rand_core::RngCore for RandOps {
    fn next_u32(&mut self) -> u32 {
        if self.begen {
            return self.gencore.as_mut().unwrap().next_u32();
        } else {
            return self.filerand.as_mut().unwrap().next_u32();
        }
    }

    fn next_u64(&mut self) -> u64 {
        if self.begen {
            return self.gencore.as_mut().unwrap().next_u64();
        }
        return self.filerand.as_mut().unwrap().next_u64();
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        if self.begen {
            return self.gencore.as_mut().unwrap().fill_bytes(dest);
        }
        return self.filerand.as_mut().unwrap().fill_bytes(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        if self.begen {
            return self.gencore.as_mut().unwrap().try_fill_bytes(dest);
        }
        return self.filerand.as_mut().unwrap().try_fill_bytes(dest);
    }
}

unsafe impl Send for RandOps {}
unsafe impl Sync for RandOps {}

fn create_randop() -> Mutex<RandOps> {
    let envname: String = "ECSIMPLE_RANDOP".to_string();
    let randop: RandOps;

    match env::var(&envname) {
        Ok(v) => {
            let randfile = Some(format!("{}", v));
            //ecsimple_log_trace!("file {}",v);
            randop = RandOps::new(randfile).unwrap();
        }
        Err(_e) => {
            //ecsimple_log_trace!("none file");
            randop = RandOps::new(None).unwrap();
        }
    }

    return Mutex::new(randop);
}

lazy_static! {
    static ref EC_SIMPLE_RANDOP: Mutex<RandOps> = create_randop();
}

pub async fn update_randop(rng: ChaCha8Rng) {
    EC_SIMPLE_RANDOP.lock().await.gencore.replace(rng);
}

#[allow(unused_assignments)]
pub fn ecsimple_rand_bits(bits: u64, top: i32, bottom: i32) -> BigInt {
    let rnbytes: usize = ((bits + 7) >> 3) as usize;
    let bit: usize = ((bits + 8 - 1) % 8) as usize;
    let mask: u32 = (0xff << (bit + 1)) as u32;

    let mut retv: Vec<u8> = { EC_SIMPLE_RANDOP.blocking_lock().get_bytes(rnbytes).unwrap() };
    ecsimple_debug_buffer_trace!(retv.as_ptr(), retv.len(), "get value");
    let mut bn: BigInt = BigInt::from_bytes_be(Sign::Plus, &retv);
    ecsimple_log_trace!(
        "random number 0x{:X} bits 0x{:x} top {} bottom {}",
        bn,
        bits,
        top,
        bottom
    );
    ecsimple_log_trace!("bit [0x{:x}] mask [0x{:x}]", bit, mask);
    if top >= 0 {
        if top > 0 {
            if bit == 0 {
                retv[0] = 0;
                retv[1] |= 0x80;
            } else {
                retv[0] |= (3 << (bit - 1)) as u8;
            }
        } else {
            retv[0] |= (1 << bit) as u8;
        }
    }
    retv[0] &= (!mask) as u8;
    ecsimple_log_trace!("buf[0] 0x{:x}", retv[0]);
    if bottom != 0 {
        retv[rnbytes - 1] |= 1;
        ecsimple_log_trace!("buf[0x{:x}] = [0x{:x}]", rnbytes - 1, retv[(rnbytes - 1)]);
    }
    bn = BigInt::from_bytes_be(Sign::Plus, &retv);
    ecsimple_log_trace!("rnd 0x{:X}", bn);
    return bn;
}

pub fn ecsimple_rand_range(rangeval: &BigInt) -> BigInt {
    loop {
        let buflen = (get_max_bits(rangeval) + 7) / 8 + 8;
        let retv = {
            EC_SIMPLE_RANDOP
                .blocking_lock()
                .get_bytes(buflen as usize)
                .unwrap()
        };
        ecsimple_debug_buffer_trace!(retv.as_ptr(), retv.len(), "get value");
        let mut bv = BigInt::from_bytes_be(Sign::Plus, &retv);
        ecsimple_log_trace!("random number 0x{:X}", bv);
        bv = bv % rangeval;
        if bv != zero() {
            ecsimple_log_trace!("result 0x{:X} range 0x{:X}", bv, rangeval);
            return bv;
        }
    }
}

pub fn ecsimple_private_rand_range(rangeval: &BigInt) -> BigInt {
    loop {
        let buflen = get_max_bits(rangeval);
        let retv: BigInt = ecsimple_rand_bits(buflen as u64, -1, 0);
        if retv < rangeval.clone() {
            return retv;
        }
        ecsimple_log_trace!("retv 0x{:X} >= rangeval 0x{:X}", retv, rangeval);
    }
}
