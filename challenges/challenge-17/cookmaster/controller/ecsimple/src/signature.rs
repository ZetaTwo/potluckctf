
use num_bigint::{BigInt,Sign,BigUint};
use asn1obj_codegen::{asn1_sequence};
use asn1obj::base::{Asn1BigNum};
use asn1obj::complex::{Asn1Seq};
use asn1obj::{asn1obj_error_class,asn1obj_new_error};
use asn1obj::asn1impl::Asn1Op;
use asn1obj::strop::asn1_format_line;
use std::io::Write;


use std::error::Error;
use crate::*;

ecsimple_error_class!{ECSignatureError}

#[derive(Clone)]
#[asn1_sequence()]
struct Asn1ECSignatureElem {
	pub r :Asn1BigNum,
	pub s :Asn1BigNum,
}

#[derive(Clone)]
#[asn1_sequence()]
struct Asn1ECSignature {
	pub elem :Asn1Seq<Asn1ECSignatureElem>,
}


pub struct ECSignature {
	pub r : BigInt,
	pub s : BigInt,
}

impl ECSignature {
	pub fn new(r :&BigInt, s :&BigInt) -> Self {
		ECSignature {
			r : r.clone(),
			s : s.clone(),
		}
	}

	pub fn decode_asn1(data :&[u8]) -> Result<ECSignature,Box<dyn Error>> {
		let mut objec :Asn1ECSignature = Asn1ECSignature::init_asn1();
		let _ = objec.decode_asn1(data)?;
		if objec.elem.val.len()!= 1 {
			ecsimple_new_error!{ECSignatureError,"elem.len [{}] != 1",objec.elem.val.len()}
		}

		let ur :Vec<u8> = objec.elem.val[0].r.val.to_bytes_be();
		let us :Vec<u8> = objec.elem.val[0].s.val.to_bytes_be();
		let r :BigInt = BigInt::from_bytes_be(Sign::Plus,&ur);
		let s :BigInt = BigInt::from_bytes_be(Sign::Plus,&us);
		Ok(ECSignature::new(&r,&s))
	}

	pub fn encode_asn1(&self) -> Result<Vec<u8>,Box<dyn Error>> {
		let mut objec :Asn1ECSignature = Asn1ECSignature::init_asn1();
		let mut elemec :Asn1ECSignatureElem = Asn1ECSignatureElem::init_asn1();
		let ur :Vec<u8>;
		let us :Vec<u8>;
		(_,ur ) = self.r.to_bytes_be();
		(_,us ) = self.s.to_bytes_be();
		elemec.r.val = BigUint::from_bytes_be(&ur);
		elemec.s.val = BigUint::from_bytes_be(&us);
		objec.elem.val.push(elemec);
		let rdata = objec.encode_asn1()?;
		Ok(rdata)
	}
}

impl std::fmt::Display for ECSignature {
	fn fmt(&self, f:&mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f,"r 0x{:X} s 0x{:X}",self.r,self.s)
	}
}


impl std::cmp::PartialEq for ECSignature {
	fn eq(&self,other :&Self) -> bool {
		let mut retv : bool = true;
		if self.r != other.r {
			retv = false;
		}

		if self.s != other.s {
			retv = false;
		}
		retv
	}

	fn ne(&self,other :&Self) -> bool {
		return ! self.eq(other);
	}
}