use num_bigint::{BigInt};
use num_traits::{one,zero};
use crate::*;
use crate::consts::*;
use crate::randop::*;
use std::error::Error;
#[allow(unused_imports)]
use crate::logger::*;

ecsimple_error_class!{MontError}

#[allow(non_snake_case)]
#[derive(Clone)]
pub struct MontNum {
	RR :BigInt,
	N :BigInt,
	R :BigInt,
	INVR :BigInt,
	BL :i64,
	FACTOR : BigInt,
	MASK :BigInt,
	CONVERTDONE :BigInt,
}

impl std::fmt::Display for MontNum {
	fn fmt(&self, f:&mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f,"N 0x{:X} R 0x{:X} INVR 0x{:X} RR 0x{:X} BL 0x{:X} FACTOR 0x{:X} MASK 0x{:X} CONVERTDONE 0x{:X}", self.N,self.R,self.INVR,self.RR,self.BL,self.FACTOR,self.MASK,self.CONVERTDONE)
	}
}

impl MontNum {
	pub fn new(modv :&BigInt) -> Result<MontNum,Box<dyn Error>> {
		let ov :BigInt = one();
		let tv :BigInt = ov.clone() + ov.clone();
		let zv :BigInt = zero();
		if (modv.clone() % &tv) == zv {
			ecsimple_new_error!{MontError,"0x{:X} not valid",modv}
		}
		let mut bl :i64 = get_max_bits(modv);
		bl = ((bl + MONT_BIT_SIZE - 1) / MONT_BIT_SIZE) * MONT_BIT_SIZE;
		let r :BigInt =  &ov << bl ;
		let rr :BigInt = &ov << (bl * 2);
		let invr :BigInt = r.modpow(&(modv.clone() - &tv), &modv);
		let factor :BigInt = (&r * &invr - &ov) / modv;
		let mask :BigInt = &r - &ov;
		let convertdone :BigInt = (&mask + &ov) % modv.clone();
		Ok(MontNum {
			R : r,
			RR : rr,
			INVR : invr,
			BL : bl,
			N : modv.clone(),
			FACTOR : factor,
			MASK : mask,
			CONVERTDONE : convertdone,
		})
	}

	pub fn mont_to(&self,bn :&BigInt) -> BigInt {
		let retv :BigInt = (bn * &self.RR * &self.INVR) % &self.N;
		return retv;
	}

	pub fn mont_from(&self,bn :&BigInt) -> BigInt {
		let retv :BigInt = (bn * &self.INVR) % &self.N;
		ecsimple_log_trace!("BN_from_montgomery(r 0x{:X},a 0x{:X},group.field 0x{:X})",retv,bn,self.N);
		return retv;
	}

	pub fn mont_mul(&self,a :&BigInt,b :&BigInt) -> BigInt {
		let an :BigInt = a % &self.N;
		let bn :BigInt = b % &self.N;
		let prod :BigInt = &an * &bn;
		let tm :BigInt = &prod & &self.MASK;
		let tf :BigInt = &tm * &self.FACTOR;
		let temp :BigInt = &tf & &self.MASK;
		let mut reduced :BigInt = (&prod + &temp * &self.N) >> self.BL;
		if reduced >= self.N {
			reduced = &reduced - &self.N;
		}
		return reduced;
	}

	pub fn mont_pow(&self,a :&BigInt,e :&BigInt) -> BigInt {
		return a.modpow(e,&self.N);
	}
}
