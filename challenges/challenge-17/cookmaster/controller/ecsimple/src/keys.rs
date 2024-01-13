

use crate::consts::*;
use crate::point::*;
use crate::group::*;
use crate::bngf2m::*;
use crate::signature::*;
use crate::utils::*;
use crate::randop::*;
use crate::logger::*;
use crate::*;
use crate::mont::*;
use crate::ecasn1::*;
use num_bigint::{BigInt,Sign,BigUint};
use num_traits::{zero,one};

use std::error::Error;

use asn1obj_codegen::{asn1_sequence};
use asn1obj::base::{Asn1BigNum,Asn1Object,Asn1Integer,Asn1BitData,Asn1BitDataFlag,Asn1Any};
use asn1obj::complex::{Asn1Seq,Asn1ImpSet};
use asn1obj::{asn1obj_error_class,asn1obj_new_error};
use asn1obj::asn1impl::Asn1Op;
use asn1obj::strop::asn1_format_line;
use std::io::Write;
use sm3::{Sm3,Digest};


ecsimple_error_class!{EcKeyError}


#[derive(Clone)]
#[asn1_sequence()]
struct ECPrivateAsn1Elem {
	pub (crate) version :Asn1Integer,
	pub (crate) privnum :Asn1BigNum,
	pub (crate) ecoid :Asn1ImpSet<Asn1Object,0>,
	pub (crate) pubdata :Asn1ImpSet<Asn1BitData,1>,
}

#[derive(Clone)]
#[asn1_sequence()]
struct ECPrivateAsn1 {
	pub (crate) elem :Asn1Seq<ECPrivateAsn1Elem>,
}


#[derive(Clone)]
pub (crate) struct ECGf2mPubKey {
	base :ECGf2mPoint,
	pubk :ECGf2mPoint,
}

impl Default for ECGf2mPubKey {
	fn default() -> Self {
		Self {
			base : ECGf2mPoint::default(),
			pubk : ECGf2mPoint::default(),
		}
	}
}

fn form_ecpkparameters_gf2m(grp :&ECGroupBnGf2m,cmprtype:&str, paramenc:&str) -> Result<ECPKPARAMETERS,Box<dyn Error>> {
	let mut tmpp :BigInt;
	let mut idx :usize;
	let mut kval :i64;
	let ov :BigInt = one();
	let mut paramselem :ECPARAMETERSElem = ECPARAMETERSElem::init_asn1();
	let mut curveelem :X9_62_CURVEElem = X9_62_CURVEElem::init_asn1();
	let mut params :ECPKPARAMETERS = ECPKPARAMETERS::init_asn1();
	let mut bevecs :Vec<u8>;
	let mut tmpu :BigUint;
	let degr :i64 = grp.degree();
	let fieldsize :usize = ((degr + 7) >> 3) as usize;
	let zv :BigInt = zero();
	if paramenc == EC_PARAMS_EXLICIT {
		/*sect163r1*/
		/*
		v8 = Vec::from_hex("0800000000000000000000000000000000000000C9").unwrap();
		p = BigInt::from_bytes_be(Sign::Plus,&v8);
		bngrp.p = p.clone();
		v8 = Vec::from_hex("07b6882caaefa84f9554ff8428bd88e246d2782ae2").unwrap();
		p = BigInt::from_bytes_be(Sign::Plus,&v8);
		bngrp.a = BnGf2m::new_from_bigint(&p);
		v8 = Vec::from_hex("0713612dcddcb40aab946bda29ca91f73af958afd9").unwrap();
		p = BigInt::from_bytes_be(Sign::Plus,&v8);
		bngrp.b = BnGf2m::new_from_bigint(&p);
		v8 = Vec::from_hex("0369979697ab43897789566789567f787a7876a654").unwrap();
		p = BigInt::from_bytes_be(Sign::Plus,&v8);
		bngrp.generator.x = BnGf2m::new_from_bigint(&p);
		v8 = Vec::from_hex("00435edb42efafb2989d51fefce3c80988f41ff883").unwrap();
		p = BigInt::from_bytes_be(Sign::Plus,&v8);
		bngrp.generator.y = BnGf2m::new_from_bigint(&p);
		bngrp.generator.z = BnGf2m::one();

		v8 = Vec::from_hex("03ffffffffffffffffffff48aab689c29ca710279b").unwrap();
		p = BigInt::from_bytes_be(Sign::Plus,&v8);
		bngrp.order = p.clone();
		bngrp.cofactor = &ov + &ov;
		bngrp.curvename = SECT163r1_NAME.to_string();

		retv.insert(SECT163r1_NAME.to_string(),bngrp.clone());
		*/
		let mut x962elem :X9_62_PENTANOMIALELem = X9_62_PENTANOMIALELem::init_asn1();
		let mut chartwo :X9_62_CHARACTERISTIC_TWO_ELEM = X9_62_CHARACTERISTIC_TWO_ELEM::init_asn1();			
		tmpp = grp.p.clone();
		kval = get_max_bits(&tmpp);
		chartwo.m.val = kval-1;
		tmpp -= ov.clone() << kval-1;
		idx = 3;
		while tmpp != ov {
			kval = get_max_bits(&tmpp);
			if idx == 3 {
				x962elem.k3.val = kval-1;
				tmpp -= ov.clone() << (kval-1);
				idx -= 1;
			} else if idx == 2 {
				x962elem.k2.val = kval-1;
				tmpp -= ov.clone() << (kval-1);
				idx -= 1;
			} else if idx == 1 {
				x962elem.k1.val = kval-1;
				tmpp -= ov.clone() << (kval-1);
				idx -= 1;
				break;
			}
		}


		if tmpp != ov {
			ecsimple_new_error!{EcKeyError,"p [0x{:x}] not 5 bits set",grp.p}
		}

		if idx == 0 {
			let _ = chartwo.elemchoice.otype.val.set_value(EC_PP_BASIS_OID)?;	
			chartwo.elemchoice.ppBasis.elem.val.push(x962elem);
		} else if idx == 2 {
			/*it is set for */
			let _ = chartwo.elemchoice.otype.val.set_value(EC_TP_BASIS_OID)?;
			bevecs = Vec::new();
			let curv = x962elem.k3.val as u64;
			for i in 0..8 {
				bevecs.push(((curv >> ((7-i)*8)) & 0xff) as u8);	
			}
			
			tmpu = BigUint::from_bytes_be(&bevecs);
			chartwo.elemchoice.tpBasis.val = tmpu.clone();
		} else if idx == 3 {
			let _ = chartwo.elemchoice.otype.val.set_value(EC_ON_BASIS_OID)?;			
		}
		
		let mut fieldidelem :X9_62_FIELDIDElem = X9_62_FIELDIDElem::init_asn1();
		let _ = fieldidelem.fieldType.val.set_value(EC_GF2M_GROUP_TYPE_OID)?;
		fieldidelem.char_two.elem.val.push(chartwo);
		paramselem.version.val = 1;
		paramselem.fieldID.elem.val.push(fieldidelem);


		tmpp = grp.a.to_bigint();
		(_,bevecs) = tmpp.to_bytes_be();
		while bevecs.len() < fieldsize {
			bevecs.insert(0,0);
		}
		curveelem.a.data = bevecs.clone();

		tmpp = grp.b.to_bigint();
		(_,bevecs) = tmpp.to_bytes_be();
		while bevecs.len() < fieldsize {
			bevecs.insert(0,0);
		}
		curveelem.b.data = bevecs.clone();

		curveelem.seed.val = None;
		if grp.seed != zv {
			let mut bitflag :Asn1BitDataFlag = Asn1BitDataFlag::init_asn1();
			(_,bevecs) = grp.seed.to_bytes_be();
			while bevecs.len() < grp.seed_len {
				bevecs.insert(0,0);
			}
			bitflag.data = bevecs.clone();
			bitflag.flag = 0;
			curveelem.seed.val = Some(bitflag.clone());
		}

		paramselem.curve.elem.val.push(curveelem);

		let x :BigInt = grp.generator.x.to_bigint();
		let y :BigInt = grp.generator.y.to_bigint();
		let basegrp :ECGf2mPubKey = ECGf2mPubKey::new(grp,&x,&y);
		let basedata :Vec<u8> = basegrp.to_bin(cmprtype)?;
		paramselem.base.data = basedata.clone();

		(_,bevecs) = grp.order.to_bytes_be();
		tmpu = BigUint::from_bytes_be(&bevecs);
		paramselem.order.val = tmpu.clone();
		(_,bevecs) = grp.cofactor.to_bytes_be();
		tmpu = BigUint::from_bytes_be(&bevecs);
		let mut bn :Asn1BigNum = Asn1BigNum::init_asn1();
		bn.val = tmpu.clone();
		paramselem.cofactor.val = Some(bn);

		params.itype = 1;
		params.parameters.elem.val.push(paramselem);
		return Ok(params);
	} else if paramenc == "" {
		params.itype = 0;
		let oid :String = ecc_get_oid_from_name(&grp.curvename)?;
		let _ = params.named_curve.set_value(&oid)?;
		return Ok(params);
	}

	ecsimple_new_error!{EcKeyError,"not supported paramenc [{}]",paramenc}
}

impl ECGf2mPubKey {
	pub (crate) fn new(grp :&ECGroupBnGf2m,x :&BigInt,y :&BigInt) -> ECGf2mPubKey {
		let b = ECGf2mPoint::new(grp);
		let xn :BnGf2m = BnGf2m::new_from_bigint(x);
		let yn :BnGf2m = BnGf2m::new_from_bigint(y);
		let zn :BnGf2m = BnGf2m::one();
		ECGf2mPubKey {
			base : b,
			pubk : ECGf2mPoint::new_point(&xn,&yn,&zn,grp),
		}
	}

	pub (crate) fn to_der(&self,cmprtype :&str,paramenc :&str) -> Result<Vec<u8>,Box<dyn Error>> {
		let mut pubkasn1 :ECPublicKeyAsn1 = ECPublicKeyAsn1::init_asn1();
		let mut pubkasn1elem :ECPublicKeyAsn1Elem = ECPublicKeyAsn1Elem::init_asn1();
		let mut packedelem :ECPublicKeyPackElem = ECPublicKeyPackElem::init_asn1();
		let _ = packedelem.typef.set_value(EC_PUBLIC_KEY_OID)?;
		let pubdata :Vec<u8> = self.to_bin(cmprtype)?;
		packedelem.parameters = form_ecpkparameters_gf2m(&self.base.group,cmprtype,paramenc)?;
		pubkasn1elem.packed.elem.val.push(packedelem);
		pubkasn1elem.pubdata.data = pubdata.clone();
		pubkasn1elem.pubdata.flag = 0;
		pubkasn1.elem.val.push(pubkasn1elem);
		return pubkasn1.encode_asn1();
	}

	fn uncompress_x_point(grp :&ECGroupBnGf2m, x_ :&BigInt, ybit :u8) -> Result<BigInt,Box<dyn Error>> {
		let b = ECGf2mPoint::new(grp);
		let xb :BnGf2m = BnGf2m::new_from_bigint(&x_);
		let field :BnGf2m = BnGf2m::new_from_bigint(&b.group.p);
		let x :BnGf2m = &xb % &field;
		let y :BigInt;
		let mut yn :BnGf2m;
		let mut tmp :BnGf2m;
		let z :BnGf2m;
		let z0 :u8;
		ecsimple_log_trace!("x 0x{:X} = x_ 0x{:X} % group->field 0x{:X}",x,x_,field);
		if x.is_zero() {
			let yn = &b.group.b.mul_op(&b.group.b).mod_op(&field);
			y = yn.to_bigint();
			ecsimple_log_trace!("y 0x{:X} = group->b 0x{:X} ^ 2 % field 0x{:X}",y,b.group.b,field);
		} else {
			tmp = b.field_sqr(&x);
			tmp = b.field_div(&b.group.b,&tmp)?;
			tmp = tmp.add_op(&b.group.a);
			ecsimple_log_trace!("tmp 0x{:X} group->a 0x{:X}",tmp,b.group.a);
			tmp = tmp.add_op(&x);
			ecsimple_log_trace!("tmp 0x{:X} x 0x{:X}",tmp,x);
			z = tmp.sqrt_quad_op(&field)?;
			ecsimple_log_trace!("z 0x{:X}",z);
			if z.is_odd() {
				z0 = 1;
			} else {
				z0 = 0;
			}
			yn = b.field_mul(&x,&z);
			if z0 != ybit {
				yn = yn.add_op(&x);
				ecsimple_log_trace!("y 0x{:X} x 0x{:X}",yn,x);
			}
			y = yn.to_bigint();
		}
		Ok(y)
	}

	pub fn from_bin(grp :&ECGroupBnGf2m, dercode :&[u8]) -> Result<Self,Box<dyn Error>> {
		let b = ECGf2mPoint::new(grp);
		let mut pubk :ECGf2mPoint = b.clone();
		if dercode.len() < 1 {
			ecsimple_new_error!{EcKeyError,"code [{}] < 1", dercode.len()}
		}
		let code :u8 = dercode[0] & EC_CODE_MASK;
		let ybit :u8 = dercode[0] & EC_CODE_YBIT;
		let degr :i64 = grp.degree();
		let fieldsize :usize = ((degr + 7) >> 3) as usize;
		let x :BigInt;
		let y :BigInt;

		if code == EC_CODE_UNCOMPRESSED {
			if dercode.len() < (1 + 2 *fieldsize) {
				ecsimple_new_error!{EcKeyError,"len [{}] < 1 + {} * 2", dercode.len(), fieldsize}
			}
			x = BigInt::from_bytes_be(Sign::Plus,&dercode[1..(fieldsize+1)]);
			ecsimple_log_trace!("x 0x{:X}",x);
			y = BigInt::from_bytes_be(Sign::Plus,&dercode[(fieldsize+1)..(2*fieldsize+1)]);
		} else if code == EC_CODE_COMPRESSED {
			if dercode.len() < (1 + fieldsize) {
				ecsimple_new_error!{EcKeyError,"len [{}] < 1 + {} ", dercode.len(), fieldsize}	
			}
			x = BigInt::from_bytes_be(Sign::Plus,&dercode[1..(fieldsize+1)]);
			ecsimple_log_trace!("x 0x{:X}",x);
			y = ECGf2mPubKey::uncompress_x_point(grp,&x,ybit)?;
		} else if code == EC_CODE_HYBRID {
			if dercode.len() < (1 + 2 * fieldsize) {
				ecsimple_new_error!{EcKeyError,"len [{}] < 1 + {} * 2", dercode.len(), fieldsize}	
			}
			x = BigInt::from_bytes_be(Sign::Plus,&dercode[1..(fieldsize+1)]);
			ecsimple_log_trace!("x 0x{:X}",x);
			y = BigInt::from_bytes_be(Sign::Plus,&dercode[(fieldsize+1)..(2*fieldsize+1)]);
			ecsimple_log_trace!("y 0x{:X}",y);
			if x == zero() && ybit != 0{
				ecsimple_new_error!{EcKeyError,"x == 0 and ybit set"}
			} else {
				let xb :BnGf2m = BnGf2m::new_from_bigint(&x);
				let yb :BnGf2m = BnGf2m::new_from_bigint(&y);
				let ybi :BnGf2m = b.field_div(&yb,&xb)?;
				ecsimple_log_trace!("yxi 0x{:X} y 0x{:X} x 0x{:X}",ybi,yb,xb);
				if (ybit != 0 && !ybi.is_odd()) || (ybit == 0 && ybi.is_odd()) {
					ecsimple_new_error!{EcKeyError,"ybi 0x{:X} not match ybit 0x{:X}", ybi,ybit}
				}
			}
		} else {
			ecsimple_new_error!{EcKeyError,"unsupport code [0x{:X}] for public point", dercode[0]}
		}
		let mut bval :BnGf2m;
		bval = BnGf2m::new_from_bigint(&x);
		pubk.set_x(&bval);
		bval = BnGf2m::new_from_bigint(&y);
		pubk.set_y(&bval);
		bval = BnGf2m::one();
		pubk.set_z(&bval);
		let _ = pubk.check_on_curve()?;
		ecsimple_log_trace!("x 0x{:X} y 0x{:X}", x,y);

		Ok(Self {
			base : b.clone(),
			pubk : pubk.clone(),
		})
	}

	pub (crate) fn to_bin(&self,cmprtype :&str) -> Result<Vec<u8>,Box<dyn Error>> {
		let mut retv :Vec<u8> = Vec::new();
		let ov :BigInt = one();
		let zv :BigInt = zero();
		let tv :BigInt = ov.clone() + ov.clone();
		let y :BigInt = self.pubk.y().to_bigint();
		let x :BigInt = self.pubk.x().to_bigint();
		let degr :i64 = self.pubk.group.degree();
		let fieldsize :usize = ((degr + 7) >> 3) as usize;
		let mut xvecs :Vec<u8>;
		let mut yvecs :Vec<u8>;
		ecsimple_log_trace!("cmprtype [{}]",cmprtype);
		if cmprtype == EC_COMPRESSED {
			retv.push(EC_CODE_COMPRESSED);
			(_, xvecs) = x.to_bytes_be();
			while xvecs.len() < fieldsize {
				xvecs.insert(0,0);
			}
			for xb in xvecs {
				retv.push(xb);
			}
			let xbn :BnGf2m = BnGf2m::new_from_bigint(&x);
			let ybn :BnGf2m = BnGf2m::new_from_bigint(&y);
			let xyibn :BnGf2m = self.pubk.field_div(&ybn,&xbn)?;
			let xyi :BigInt = xyibn.to_bigint();
			ecsimple_log_trace!("field_div(xyi 0x{:X},y 0x{:X},x 0x{:X})",xyibn,ybn,xbn);
			if xyi % tv != zv {
				retv[0] |= EC_CODE_YBIT;
			}
		} else if cmprtype == EC_UNCOMPRESSED {
			retv.push(EC_CODE_UNCOMPRESSED);
			(_,xvecs) = x.to_bytes_be();
			while xvecs.len() < fieldsize {
				xvecs.insert(0,0);
			}
			for xb in xvecs {
				retv.push(xb);
			}
			(_,yvecs) = y.to_bytes_be();
			while yvecs.len() < fieldsize {
				yvecs.insert(0,0);
			}
			for yb in yvecs {
				retv.push(yb);
			}
		} else if cmprtype == EC_HYBRID {
			retv.push(EC_CODE_HYBRID);
			(_,xvecs) = x.to_bytes_be();
			while xvecs.len() < fieldsize {
				xvecs.insert(0,0);
			}
			for xb in xvecs {
				retv.push(xb);
			}
			(_,yvecs) = y.to_bytes_be();
			while yvecs.len() < fieldsize {
				yvecs.insert(0,0);
			}
			for yb in yvecs {
				retv.push(yb);
			}
			let xbn :BnGf2m = BnGf2m::new_from_bigint(&x);
			let ybn :BnGf2m = BnGf2m::new_from_bigint(&y);
			let xyibn :BnGf2m = self.pubk.field_div(&ybn,&xbn)?;
			let xyi :BigInt = xyibn.to_bigint();
			ecsimple_log_trace!("field_div(xyi 0x{:X},y 0x{:X},x 0x{:X})",xyibn,ybn,xbn);
			if xyi % tv != zv {
				retv[0] |= EC_CODE_YBIT;
			}
		} else {
			ecsimple_new_error!{EcKeyError,"not supported cmprtype [{}]",cmprtype}
		}
		ecsimple_debug_buffer_trace!(retv.as_ptr(),retv.len(),"outbin");
		Ok(retv)
	}


	pub (crate) fn verify_base(&self,sig :&ECSignature, hashnum :&[u8]) -> Result<bool,Box<dyn Error>> {
		let mut u2 :BigInt;
		let order :BigInt = self.base.group.order.clone();
		let vfypnt :ECGf2mPoint;
		ecsimple_log_trace!("sig.r 0x{:X} sig.s 0x{:X}", sig.r,sig.s);
		if sig.r == zero() || sig.s == zero() {
			ecsimple_new_error!{EcKeyError,"sig.r 0x{:X} or sig.s 0x{:X} zero",sig.r,sig.s}
		}

		let e :BigInt = &order - 2;
		u2 = sig.s.modpow(&e,&order);
		ecsimple_log_trace!("s 0x{:X} u2 0x{:X}",sig.s,u2);
		let m :BigInt = format_bigint_as_order(hashnum,&order);
		ecsimple_log_trace!("dgst 0x{:X}",m);

		let mut u1 :BigInt = (&u2 * &m) % &order;
		ecsimple_log_trace!("u1 0x{:X} = m 0x{:X} * tmp 0x{:X} % order 0x{:X}", u1,m,u2,order);

		u2 = &(&u2 * &sig.r) % &order;
		ecsimple_log_trace!("u2 0x{:X} sig->r 0x{:X} order 0x{:X}", u2,sig.r,order);

		vfypnt = self.pubk.mulex_op(&u1,&u2)?;
		let xn :BigInt = vfypnt.x().to_bigint();
		u1 = &xn % &order;
		ecsimple_log_trace!("u1 0x{:X} = X 0x{:X} % order 0x{:X} sig->r 0x{:X}",u1,xn,order,sig.r);
		if u1 != sig.r {
			return Ok(false);
		}
		Ok(true)
	}

}

impl std::fmt::Display for ECGf2mPubKey {
	fn fmt(&self, f:&mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f,"base {};\npoint {};\n",self.base,self.pubk)
	}
}



#[derive(Clone)]
pub (crate) struct ECGf2mPrivateKey {
	base : ECGf2mPoint,
	privnum :BigInt,
}

impl Default for ECGf2mPrivateKey {
	fn default() -> Self {
		let ov :BigInt = one();
		Self {
			base : ECGf2mPoint::default(),
			privnum : ov,
		}
	}
}

impl std::fmt::Display for ECGf2mPrivateKey {
	fn fmt(&self, f:&mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f,"base {};\nprivnum {};\n",self.base,self.privnum)
	}
}



impl ECGf2mPrivateKey {
	pub (crate) fn new(grp :&ECGroupBnGf2m , privnum :&BigInt) -> ECGf2mPrivateKey {
		let b :ECGf2mPoint = ECGf2mPoint::new(grp);
		ECGf2mPrivateKey {
			base : b,
			privnum : privnum.clone(),
		}
	}

	pub (crate) fn generate(grp :&ECGroupBnGf2m) -> ECGf2mPrivateKey {
		let b :ECGf2mPoint = ECGf2mPoint::new(grp);
		let mut privnum :BigInt;
		let zv :BigInt = zero();
		loop {
			privnum = ecsimple_rand_range(&grp.order);
			if privnum != zv {
				break;
			}
		}
		ECGf2mPrivateKey {
			base :b ,
			privnum : privnum,
		}
	}

	pub fn export_pubkey(&self) -> ECGf2mPubKey {
		let ck : ECGf2mPoint;
		ck = self.base.mul_op(&self.privnum,false);
		let retv :ECGf2mPubKey = ECGf2mPubKey {
			base : self.base.clone(),
			pubk : ck.clone(),
		};
		retv
	}

	pub (crate)  fn to_der(&self,cmprtype :&str,paramenc :&str) -> Result<Vec<u8>,Box<dyn Error>> {
		let pubk :ECGf2mPubKey = self.export_pubkey();
		//let pubdata :Vec<u8> = pubk.to_bin(cmprtype)?;
		let privlen :usize = ((get_max_bits(&self.base.group.order) + 7 ) >> 3) as usize;
		let pubdata :Vec<u8>;
		if paramenc == EC_PARAMS_EXLICIT {
			//pubdata  = pubk.to_bin(EC_UNCOMPRESSED)?;
			pubdata = pubk.to_bin(cmprtype)?;
		} else {
			pubdata = pubk.to_bin(cmprtype)?;
		}
		
		let mut ecprivasn1elem :ECPrivateKeyAsn1Elem = ECPrivateKeyAsn1Elem::init_asn1();
		let mut ecprivasn1 :ECPrivateKeyAsn1 = ECPrivateKeyAsn1::init_asn1();
		let mut bevecs :Vec<u8>;
		let params :ECPKPARAMETERS;
		let mut impparams :Asn1ImpSet<ECPKPARAMETERS,0> = Asn1ImpSet::init_asn1();
		let mut asn1pubdata : Asn1BitDataFlag = Asn1BitDataFlag::init_asn1();
		params = form_ecpkparameters_gf2m(&self.base.group,cmprtype,paramenc)?;
		ecprivasn1elem.version.val = 1;
		(_,bevecs) = self.privnum.to_bytes_be();
		while bevecs.len() < privlen {
			bevecs.insert(0,0);
		}
		ecprivasn1elem.privkey.data = bevecs.clone();
		impparams.val.push(params);
		ecprivasn1elem.parameters.val = Some(impparams);
		asn1pubdata.data = pubdata.clone();
		asn1pubdata.flag = 0;
		//imppubk.val.push(asn1pubdata);
		ecprivasn1elem.pubkey.val.push(asn1pubdata);
		ecprivasn1.elem.val.push(ecprivasn1elem);
		return ecprivasn1.encode_asn1();
	}


	#[allow(unused_variables)]
	#[allow(unused_assignments)]
	#[allow(non_snake_case)]
	fn setup_sign(&self) -> Result<(BigInt,BigInt),Box<dyn Error>> {
		let mut r :BigInt;
		let mut tmppnt :ECGf2mPoint = self.base.clone();
		let zv :BnGf2m = BnGf2m::zero();
		let ov :BigInt = one();
		tmppnt.set_x(&zv);
		tmppnt.set_y(&zv);
		tmppnt.set_z(&zv);
		let mut k  :BigInt ;
		let mut X :BnGf2m;
		let blen = get_max_bits(&self.base.group.order);
		ecsimple_log_trace!("tmp.x 0x{:X} tmp.y 0x{:X}, tmp.z 0x{:X}", tmppnt.x(),tmppnt.y(),tmppnt.z());
		ecsimple_log_trace!("order 0x{:X}",self.base.group.order);
		k = ov << blen;
		loop {
			ecsimple_log_trace!("k 0x{:X}",k);
			k = ecsimple_rand_range(&self.base.group.order);
			ecsimple_log_trace!("k 0x{:X} order 0x{:X} dlen 0x{:x}", k, self.base.group.order,((blen + 7 ) >> 3) as i64);

			ecsimple_log_trace!("group.x 0x{:X} group.y 0x{:X} group.z 0x{:X}", self.base.group.generator.x,self.base.group.generator.y,self.base.group.generator.z);
			tmppnt = self.base.mul_op(&k,false);
			ecsimple_log_trace!("tmp.x 0x{:X} tmp.y 0x{:X} tmp.z 0x{:X}", tmppnt.x(),tmppnt.y(),tmppnt.z());

			(X,_) = tmppnt.get_affine_points()?;

			ecsimple_log_trace!("tmp.x 0x{:X} tmp.y 0x{:X} tmp.z 0x{:X}", tmppnt.x(),tmppnt.y(),tmppnt.z());
			ecsimple_log_trace!("X 0x{:X} order 0x{:X}",X,self.base.group.order);


			let xb :BigInt = X.to_bigint();

			r = xb % &self.base.group.order;


			if r != zero() {
				break;
			}
		}

		ecsimple_log_trace!("X 0x{:X} r 0x{:X}", X,r);

		let e :BigInt = &self.base.group.order - 2;
		let kn = k.clone();

		k = k.modpow(&e,&self.base.group.order);
		ecsimple_log_trace!("(x 0x{:X} ^ e 0x{:X}) = (r 0x{:X}) = 1 % order 0x{:X}",kn,e,k,self.base.group.order);
		ecsimple_log_trace!("k 0x{:X} r 0x{:X}",k,r);
		Ok((k,r))
	}

	#[allow(unused_assignments)]
	pub fn sign_base(&self,hashnum :&[u8]) -> Result<ECSignature,Box<dyn Error>> {
		//let bn :BigInt = BigInt::from_bytes_be(Sign::Plus,hashnum);
		ecsimple_log_trace!("begin sign");
		let mut s :BigInt = zero();
		let mut r :BigInt = zero();
		ecsimple_log_trace!("r 0x{:X} s 0x{:X}",r,s);
		ecsimple_log_trace!("order 0x{:X}", self.base.group.order);

		let realhash = format_bigint_as_order(hashnum,&self.base.group.order);
		ecsimple_log_trace!("dgst 0x{:X}", realhash);

		/*we may be last update*/
		//assert!(realhash <= self.base.group.order);
		let kinv :BigInt;
		(kinv,r) = self.setup_sign()?;
		ecsimple_log_trace!("ckinv 0x{:X} r 0x{:X}",kinv,r);
		s = (&realhash + &self.privnum * &r) % &self.base.group.order;
		ecsimple_log_trace!("s 0x{:X}",s);
		s = (&s * &kinv) % &self.base.group.order;
		ecsimple_log_trace!("s 0x{:X}",s);


		let retv :ECSignature = ECSignature::new(&r,&s);
		Ok(retv)
	}
}


#[derive(Clone)]
pub (crate) struct ECPrimePubKey {
	base :ECPrimePoint,
	pubk :ECPrimePoint,
}

impl Default for ECPrimePubKey {
	fn default() -> Self {
		Self {
			base : ECPrimePoint::default(),
			pubk : ECPrimePoint::default(),
		}
	}
}

fn form_ecpkparameters_prime(grp :&ECGroupPrime,cmprtype :&str,paramenc :&str) -> Result<ECPKPARAMETERS,Box<dyn Error>> {
	let montv :MontNum;
	let mut tmpu :BigUint;
	let mut tmpp :BigInt;
	let mut bevecs :Vec<u8>;
	let mut paramselem :ECPARAMETERSElem = ECPARAMETERSElem::init_asn1();
	let mut params :ECPKPARAMETERS = ECPKPARAMETERS::init_asn1();
	let mut asn1pubdata :Asn1BitDataFlag = Asn1BitDataFlag::init_asn1();
	let zv :BigInt = zero();
	let degr :i64 = grp.degree();
	let fieldsize :usize = ((degr + 7) >> 3) as usize;
	montv = MontNum::new(&grp.p).unwrap();

	/*secp224r1*/
	/*
	v8 = Vec::from_hex("ffffffffffffffffffffffffffffffff000000000000000000000001").unwrap();
	p = BigInt::from_bytes_be(Sign::Plus,&v8);
	bngrp.p = p.clone();
	montv = MontNum::new(&bngrp.p).unwrap();
	tmpp = p.clone();
	v8 = Vec::from_hex("fffffffffffffffffffffffffffffffefffffffffffffffffffffffe").unwrap();
	p = BigInt::from_bytes_be(Sign::Plus,&v8);
	tmpa = p.clone();
	bngrp.a = montv.mont_to(&p);
	v8 = Vec::from_hex("b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4").unwrap();
	p = BigInt::from_bytes_be(Sign::Plus,&v8);
	bngrp.b = montv.mont_to(&p);
	v8 = Vec::from_hex("b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21").unwrap();
	p = BigInt::from_bytes_be(Sign::Plus,&v8);
	bngrp.generator.x = montv.mont_to(&p);
	v8 = Vec::from_hex("bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34").unwrap();
	p = BigInt::from_bytes_be(Sign::Plus,&v8);
	bngrp.generator.y = montv.mont_to(&p);
	bngrp.generator.z = montv.mont_to(&ov);
	v8 = Vec::from_hex("ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d").unwrap();
	p = BigInt::from_bytes_be(Sign::Plus,&v8);
	bngrp.order = p.clone();
	bngrp.cofactor = ov.clone();
	bngrp.curvename = SECP224r1_NAME.to_string();
	//ecsimple_log_trace!("tmpp 0x{:X} tmpa 0x{:X}",tmpp,tmpa);
	if tmpp == (tmpa.clone() + ov.clone() + ov.clone() + ov.clone()) {
		bngrp.is_minus3 = true;
		//ecsimple_log_trace!("{} is_minus3 true",SECP224r1_NAME);
	} else {
		bngrp.is_minus3 = false;
		//ecsimple_log_trace!("{} is_minus3 false",SECP224r1_NAME);
	}
	retv.insert(SECP224r1_NAME.to_string(),bngrp.clone());
	*/
	if paramenc == EC_PARAMS_EXLICIT {
		let mut fieldidelem :X9_62_FIELDIDElem = X9_62_FIELDIDElem::init_asn1();
		let _ = fieldidelem.fieldType.val.set_value(EC_PRIME_GROUP_TYPE_OID)?;
		(_,bevecs) = grp.p.to_bytes_be();
		tmpu = BigUint::from_bytes_be(&bevecs);
		fieldidelem.prime.val = tmpu.clone();
		paramselem.fieldID.elem.val.push(fieldidelem);
		paramselem.version.val = 1;
		let mut curveelem :X9_62_CURVEElem = X9_62_CURVEElem::init_asn1();
		tmpp = montv.mont_from(&grp.a);
		(_,bevecs) = tmpp.to_bytes_be();
		while bevecs.len() < fieldsize {
			bevecs.insert(0,0);
		}
		curveelem.a.data = bevecs.clone();
		tmpp = montv.mont_from(&grp.b);
		(_,bevecs) = tmpp.to_bytes_be();
		while bevecs.len() < fieldsize {
			bevecs.insert(0,0);
		}
		curveelem.b.data = bevecs.clone();

		if grp.seed == zv {
			curveelem.seed.val = None;	
		} else {
			(_,bevecs) = grp.seed.to_bytes_be();
			while bevecs.len() < grp.seed_len {
				bevecs.insert(0,0);
			}
			asn1pubdata.data = bevecs.clone();
			asn1pubdata.flag = 0;
			curveelem.seed.val = Some(asn1pubdata.clone());
		}
		

		paramselem.curve.elem.val.push(curveelem);

		//let x :BigInt = montv.mont_from(&grp.generator.x);
		//let y :BigInt = montv.mont_from(&grp.generator.y);
		/*because in to_bin we get the get_affine_coordinates so this would not let go*/
		let x:BigInt = grp.generator.x.clone();
		let y:BigInt = grp.generator.y.clone();
		let basegrp :ECPrimePubKey = ECPrimePubKey::new(grp,&x,&y);
		let basedata :Vec<u8> = basegrp.to_bin(cmprtype)?;
		paramselem.base.data = basedata.clone();
		(_,bevecs) = grp.order.to_bytes_be();
		tmpu = BigUint::from_bytes_be(&bevecs);
		paramselem.order.val = tmpu.clone();

		(_,bevecs) = grp.cofactor.to_bytes_be();
		tmpu = BigUint::from_bytes_be(&bevecs);
		let mut bn :Asn1BigNum = Asn1BigNum::init_asn1();
		bn.val = tmpu.clone();
		paramselem.cofactor.val = Some(bn);

		params.itype = 1;
		params.parameters.elem.val.push(paramselem);
		return Ok(params);
	} else if paramenc == "" {
		params.itype = 0;
		let oid :String = ecc_get_oid_from_name(&grp.curvename)?;
		let _ = params.named_curve.set_value(&oid)?;
		return Ok(params);

	}
	ecsimple_new_error!{EcKeyError,"not supported paramenc type [{}]",paramenc}

}


impl ECPrimePubKey {
	pub (crate) fn new(grp :&ECGroupPrime,x :&BigInt,y :&BigInt) -> ECPrimePubKey {
		let b = ECPrimePoint::new(grp);
		let zn :BigInt = one();
		ECPrimePubKey {
			base : b,
			pubk : ECPrimePoint::new_point(&x,&y,&zn,grp),
		}
	}

	pub (crate) fn to_der(&self,cmprtype :&str,paramenc :&str) -> Result<Vec<u8>,Box<dyn Error>> {
		let basegrp :ECGroup = ecc_get_curve_group(SM2_NAME)?;
		let sm2grp :ECGroupPrime = basegrp.get_prime_group();
		if self.base.group != sm2grp {
			let mut pubkasn1 :ECPublicKeyAsn1 = ECPublicKeyAsn1::init_asn1();
			let mut pubkasn1elem :ECPublicKeyAsn1Elem = ECPublicKeyAsn1Elem::init_asn1();
			let mut packedelem :ECPublicKeyPackElem = ECPublicKeyPackElem::init_asn1();
			let _ = packedelem.typef.set_value(EC_PUBLIC_KEY_OID)?;
			let pubdata :Vec<u8> = self.to_bin(cmprtype)?;
			packedelem.parameters = form_ecpkparameters_prime(&self.base.group,cmprtype,paramenc)?;
			pubkasn1elem.packed.elem.val.push(packedelem);
			pubkasn1elem.pubdata.data = pubdata.clone();
			pubkasn1elem.pubdata.flag = 0;
			pubkasn1.elem.val.push(pubkasn1elem);
			return pubkasn1.encode_asn1();			
		} else {
			let mut pubkasn1 :ECPublicKeyAsn1 = ECPublicKeyAsn1::init_asn1();
			let mut pubkasn1elem :ECPublicKeyAsn1Elem = ECPublicKeyAsn1Elem::init_asn1();
			let mut packedelem :ECPublicKeyPackElem = ECPublicKeyPackElem::init_asn1();
			let _ = packedelem.typef.set_value(SM2_OID)?;
			let pubdata :Vec<u8> = self.to_bin(cmprtype)?;
			packedelem.parameters = form_ecpkparameters_prime(&self.base.group,cmprtype,paramenc)?;
			pubkasn1elem.packed.elem.val.push(packedelem);
			pubkasn1elem.pubdata.data = pubdata.clone();
			pubkasn1elem.pubdata.flag = 0;
			pubkasn1.elem.val.push(pubkasn1elem);
			return pubkasn1.encode_asn1();			
		}
	}

	fn uncompress_x_point(grp :&ECGroupPrime, x_ :&BigInt, ybit :u8) -> Result<BigInt,Box<dyn Error>> {
		let b = ECPrimePoint::new(grp);
		let field :BigInt = b.group.p.clone();
		let x :BigInt = nmod(&x_,&grp.p);
		ecsimple_log_trace!("nnmod(x 0x{:X},x_ 0x{:X},group.field 0x{:X})", x,x_,grp.p);
		let mut y :BigInt;
		let mut tmp2 :BigInt;
		let mut tmp1 :BigInt;
		let mut kbit :i32;
		let zv :BigInt = zero();
		tmp2 = (x_.clone() * x_.clone()) % &field;
		ecsimple_log_trace!("mod_sqr(tmp2 0x{:X},x_ 0x{:X},group.field 0x{:X})",tmp2,x_,grp.p);
		tmp1 = (tmp2.clone() * x_.clone()) % &field;
		ecsimple_log_trace!("mod_mul(tmp1 0x{:X},tmp2 0x{:X},x_ 0x{:X},group.field 0x{:X})",tmp1,tmp2,x_,field);
		if grp.is_minus3 {
			tmp2 = b.lshift1_mod_quick(&x,&field);
			ecsimple_log_trace!("lshift1_mod_quick(tmp2 0x{:X},x 0x{:X},group.field 0x{:X})",tmp2,x,field);
			tmp2 = b.add_mod_quick(&tmp2,&x,&field);
			ecsimple_log_trace!("add_mod_quick(tmp2 0x{:X},tmp2,x 0x{:X},group.field 0x{:X})",tmp2,x,field);
			tmp1 = b.sub_mod_quick(&tmp1,&tmp2,&field);
			ecsimple_log_trace!("sub_mod_quick(tmp1 0x{:X},tmp1,tmp2 0x{:X},group.field 0x{:X})",tmp1,tmp2,field);
		} else {
			tmp2 = b.field_decode(&grp.a);
			tmp2 = (tmp2.clone() * x.clone()) % &field;
			ecsimple_log_trace!("mod_mul(tmp2 0x{:X},tmp2,x 0x{:X},group.field 0x{:X})",tmp2,x,field);

			tmp1 = b.add_mod_quick(&tmp1,&tmp2,&field);
			ecsimple_log_trace!("add_mod_quick(tmp1 0x{:X},tmp1,tmp2 0x{:X},group.field 0x{:X})",tmp1,tmp2,field);
		}

		tmp2 = b.field_decode(&grp.b);
		tmp1 = b.add_mod_quick(&tmp1,&tmp2,&field);
		ecsimple_log_trace!("add_mod_quick(tmp1 0x{:X},tmp1,tmp2 0x{:X},group.field 0x{:X})",tmp1,tmp2,field);

		y = mod_sqrt(&tmp1,&field)?;
		ecsimple_log_trace!("mod_sqr(y 0x{:X},tmp1 0x{:X},group.field 0x{:X})",y,tmp1,field);
		kbit = get_bit_set(&y,0);
		if kbit != ybit as i32 {
			if y == zv {
				ecsimple_new_error!{EcKeyError,"not valid y 0x{:X}",y}
			}
			y = &field - &y;
			ecsimple_log_trace!("usub(y 0x{:X},group.field 0x{:X},y)",y,field);
		}
		kbit = get_bit_set(&y,0);
		if kbit != ybit as i32 {
			ecsimple_new_error!{EcKeyError,"y 0x{:X} not valid for bit",y}
		}

		Ok(y)
	}

	pub fn from_bin(grp :&ECGroupPrime, dercode :&[u8]) -> Result<Self,Box<dyn Error>> {
		let b = ECPrimePoint::new(grp);
		let pubk :ECPrimePoint = b.clone();
		if dercode.len() < 1 {
			ecsimple_new_error!{EcKeyError,"code [{}] < 1", dercode.len()}
		}
		let code :u8 = dercode[0] & EC_CODE_MASK;
		let ybit :u8 = dercode[0] & EC_CODE_YBIT;
		let degr :i64 = grp.degree();
		let fieldsize :usize = ((degr + 7) >> 3) as usize;
		let x :BigInt;
		let y :BigInt;
		ecsimple_log_trace!("grp degree [0x{:x}] fieldsize 0x{:x}", degr,fieldsize);

		if code == EC_CODE_UNCOMPRESSED {
			if dercode.len() < (1 + 2 *fieldsize) {
				ecsimple_new_error!{EcKeyError,"len [{}] < 1 + {} * 2", dercode.len(), fieldsize}
			}
			x = BigInt::from_bytes_be(Sign::Plus,&dercode[1..(fieldsize+1)]);
			ecsimple_log_trace!("x 0x{:X}",x);
			y = BigInt::from_bytes_be(Sign::Plus,&dercode[(fieldsize+1)..(2*fieldsize+1)]);
		} else if code == EC_CODE_COMPRESSED {
			if dercode.len() < (1 + fieldsize) {
				ecsimple_new_error!{EcKeyError,"len [{}] < 1 + {} ", dercode.len(), fieldsize}	
			}
			x = BigInt::from_bytes_be(Sign::Plus,&dercode[1..(fieldsize+1)]);
			ecsimple_log_trace!("x 0x{:X}",x);
			y = ECPrimePubKey::uncompress_x_point(grp,&x,ybit)?;
		} else if code == EC_CODE_HYBRID {
			if dercode.len() < (1 + 2 * fieldsize) {
				ecsimple_new_error!{EcKeyError,"len [{}] < 1 + {} * 2", dercode.len(), fieldsize}	
			}
			x = BigInt::from_bytes_be(Sign::Plus,&dercode[1..(fieldsize+1)]);
			ecsimple_log_trace!("x 0x{:X}",x);
			y = BigInt::from_bytes_be(Sign::Plus,&dercode[(fieldsize+1)..(2*fieldsize+1)]);
			ecsimple_log_trace!("y 0x{:X}",y);
			if x == zero() && ybit != 0{
				ecsimple_new_error!{EcKeyError,"x == 0 and ybit set"}
			} else {
			}
		} else {
			ecsimple_new_error!{EcKeyError,"unsupport code [0x{:X}] for public point", dercode[0]}
		}
		let z :BigInt = one();
		let pubk = pubk.set_affine_coordinates(&x,&y,&z)?;
		let _ = pubk.check_on_curve()?;
		ecsimple_log_trace!("pubkey.x 0x{:X} pubkey.y 0x{:X} pubkey.z 0x{:X}",pubk.x(),pubk.y(),pubk.z());

		Ok(Self {
			base : b.clone(),
			pubk : pubk.clone(),
		})
	}


	pub (crate) fn to_bin(&self,cmprtype :&str) -> Result<Vec<u8>,Box<dyn Error>> {
		let mut retv :Vec<u8> = Vec::new();
		let affinpnt :ECPrimePoint = self.pubk.get_affine_coordinates(&self.pubk);
		let x :BigInt = affinpnt.x();
		let y :BigInt = affinpnt.y();
		let ov :BigInt = one();
		let zv :BigInt = zero();
		let tv :BigInt = ov.clone() + ov.clone();
		let degr :i64 = self.pubk.group.degree();
		let fieldsize :usize = ((degr + 7) >> 3) as usize;
		let mut xvecs :Vec<u8>;
		let mut yvecs :Vec<u8>;

		if cmprtype == EC_COMPRESSED {
			retv.push(EC_CODE_COMPRESSED);
			(_,xvecs) = x.to_bytes_be();
			while xvecs.len() < fieldsize {
				xvecs.insert(0,0);
			}
			for xb in xvecs {
				retv.push(xb);
			}
			if y % tv != zv {
				retv[0] |= EC_CODE_YBIT;
			}
		} else if cmprtype == EC_UNCOMPRESSED {
			retv.push(EC_CODE_UNCOMPRESSED);
			(_,xvecs) = x.to_bytes_be();
			while xvecs.len() < fieldsize {
				xvecs.insert(0,0);
			}

			for xb in xvecs {
				retv.push(xb);
			}
			(_,yvecs) = y.to_bytes_be();
			while yvecs.len() < fieldsize {
				yvecs.insert(0,0);
			}
			for yb in yvecs {
				retv.push(yb);
			}
		} else if cmprtype == EC_HYBRID {
			retv.push(EC_CODE_HYBRID);
			(_,xvecs) = x.to_bytes_be();
			while xvecs.len() < fieldsize {
				xvecs.insert(0,0);
			}
			for xb in xvecs {
				retv.push(xb);
			}
			(_,yvecs) = y.to_bytes_be();
			while yvecs.len() < fieldsize {
				yvecs.insert(0,0);
			}
			for yb in yvecs {
				retv.push(yb);
			}
			if y % tv != zv {
				retv[0] |= EC_CODE_YBIT;
			}
		} else {
			ecsimple_new_error!{EcKeyError,"not supported cmprtype [{}]",cmprtype}
		}
		Ok(retv)
	}


	#[allow(unused_variables)]
	pub fn verify_base(&self,sig :&ECSignature, hashnum :&[u8]) -> Result<bool,Box<dyn Error>> {
		let mut u2 :BigInt;
		let order :BigInt = self.base.group.order.clone();
		let x :BigInt;
		ecsimple_log_trace!("sig.r 0x{:X} sig.s 0x{:X}", sig.r,sig.s);
		if sig.r == zero() || sig.s == zero() {
			ecsimple_new_error!{EcKeyError,"sig.r 0x{:X} or sig.s 0x{:X} zero",sig.r,sig.s}
		}

		let e :BigInt = &order - 2;
		u2 = sig.s.modpow(&e,&order);
		ecsimple_log_trace!("s 0x{:X} u2 0x{:X}",sig.s,u2);
		let m :BigInt = format_bigint_as_order(hashnum,&order);
		ecsimple_log_trace!("dgst 0x{:X}",m);

		let mut u1 :BigInt = (&u2 * &m) % &order;
		ecsimple_log_trace!("u1 0x{:X} = m 0x{:X} * tmp 0x{:X} % order 0x{:X}", u1,m,u2,order);

		u2 = &(&u2 * &sig.r) % &order;
		ecsimple_log_trace!("u2 0x{:X} sig->r 0x{:X} order 0x{:X}", u2,sig.r,order);
		let vfypnt :ECPrimePoint;

		vfypnt = self.pubk.mulex_op(&u1,&u2)?;
		(x,_) = vfypnt.get_affine_points()?;
		if x != sig.r {
			u1 = x.clone() % self.base.group.order.clone();
			ecsimple_log_trace!("u1 0x{:X} = X 0x{:X} % order 0x{:X} sig->r 0x{:X}",u1,x,self.base.group.order,sig.r);
			if u1 != sig.r {
				ecsimple_log_error!("x 0x{:X} != sig.r 0x{:X}", u1,sig.r);
				return Ok(false);				
			}
		}
		Ok(true)
	}

	#[allow(unused_variables)]
	pub (crate) fn verify_sm2_base(&self, sig :&ECSignature,hashnum :&[u8]) -> Result<bool,Box<dyn Error>> {
		let e :BigInt = BigInt::from_bytes_be(Sign::Plus,hashnum);
		let ov :BigInt = one();
		let zv :BigInt = zero();
		let order :BigInt = self.base.group.order.clone();
		let mut t :BigInt;
		let mut retv :bool = false;
		let x1 :BigInt;
	    /*
	     * B1: verify whether r' in [1,n-1], verification failed if not
	     * B2: verify whether s' in [1,n-1], verification failed if not
	     * B3: set M'~=ZA || M'
	     * B4: calculate e'=Hv(M'~)
	     * B5: calculate t = (r' + s') modn, verification failed if t=0
	     * B6: calculate the point (x1', y1')=[s']G + [t]PA
	     * B7: calculate R=(e'+x1') modn, verification pass if yes, otherwise failed
	     */

		if sig.r  < ov || sig.r >= order {
			ecsimple_new_error!{EcKeyError,"r 0x{:X} < 1 || > order 0x{:X}",sig.r,order}
		}

		if sig.s < ov || sig.s >= order {
			ecsimple_new_error!{EcKeyError,"s 0x{:X} < 1 || > order 0x{:X}",sig.s,order}
		}

		t = (&sig.r + &sig.s) % &order;
		ecsimple_log_trace!("BN_mod_add(t 0x{:X},r 0x{:X},s 0x{:X},order 0x{:X})",t,sig.r,sig.s,order);
		if t == zv {
			ecsimple_new_error!{EcKeyError,"t == 0"}
		}
		let pnt = self.pubk.mulex_op(&sig.s,&t)?;
		(x1,_) = pnt.get_affine_points()?;
		ecsimple_log_trace!("x1 0x{:X}",x1);

		t = (&e + &x1) % &order;
		ecsimple_log_trace!("BN_mod_add(t 0x{:X},e 0x{:X},x1 0x{:X},order 0x{:X})",t,e,x1,order);

		if t == sig.r {
			retv = true;
		}
		Ok(retv)
	}

	#[allow(non_snake_case)]
	pub (crate) fn get_sm3_hashcode(&self,idv :&[u8]) -> Result<Vec<u8>,Box<dyn Error>> {
		let retv :Vec<u8>;
		let mut inputv :Vec<u8> = Vec::new();
		let idlen :usize = idv.len();
		let order :BigInt = self.base.group.p.clone();
		let orderlen :usize = ((get_max_bits(&order) + 7) >> 3) as usize;
		let mut bufv :Vec<u8>;
		let idvec :Vec<u8>;
		let montv :MontNum;
		montv = MontNum::new(&order)?;
		let a:BigInt = montv.mont_from(&self.base.group.a);
		let b:BigInt = montv.mont_from(&self.base.group.b);
		/*first for the length of id, no id*/
		inputv.push(((idlen >> 8) & 0xff) as u8);
		ecsimple_debug_buffer_trace!(inputv.as_ptr(),inputv.len(),"idlen >> 8 number");
		inputv.push((idlen & 0xff) as u8);
		ecsimple_debug_buffer_trace!(inputv[1..].as_ptr(),inputv.len()-1,"idlen & 0xff number");
		idvec = idv.to_vec();
		ecsimple_debug_buffer_trace!(idvec.as_ptr(),idvec.len(),"id len");
		inputv.extend(idvec);
		(_,bufv) = a.to_bytes_be();
		while bufv.len() < orderlen {
			bufv.insert(0,0);
		}
		ecsimple_debug_buffer_trace!(bufv.as_ptr(),bufv.len(),"a number");
		inputv.extend(bufv.clone());
		(_,bufv) = b.to_bytes_be();
		while bufv.len() < orderlen {
			bufv.insert(0,0);
		}
		ecsimple_debug_buffer_trace!(bufv.as_ptr(),bufv.len(),"b number");
		inputv.extend(bufv.clone());
		let mut corpnt :ECPrimePoint;
		corpnt = self.base.get_affine_coordinates(&self.base);
		let xG :BigInt = corpnt.x();
		let yG :BigInt = corpnt.y();
		(_,bufv) = xG.to_bytes_be();
		while bufv.len() < orderlen {
			bufv.insert(0,0);
		}
		ecsimple_debug_buffer_trace!(bufv.as_ptr(),bufv.len(),"xG number");
		inputv.extend(bufv.clone());
		(_,bufv) = yG.to_bytes_be();
		while bufv.len() < orderlen {
			bufv.insert(0,0);
		}
		ecsimple_debug_buffer_trace!(bufv.as_ptr(),bufv.len(),"yG number");
		inputv.extend(bufv.clone());
		corpnt = self.pubk.get_affine_coordinates(&self.pubk);
		let xA :BigInt = corpnt.x();
		let yA :BigInt = corpnt.y();
		(_,bufv) = xA.to_bytes_be();
		while bufv.len() < orderlen {
			bufv.insert(0,0);
		}
		ecsimple_debug_buffer_trace!(bufv.as_ptr(),bufv.len(),"xA number");
		inputv.extend(bufv.clone());
		(_,bufv) = yA.to_bytes_be();
		while bufv.len() < orderlen {
			bufv.insert(0,0);
		}
		ecsimple_debug_buffer_trace!(bufv.as_ptr(),bufv.len(),"yA number");
		inputv.extend(bufv.clone());
		let mut hasher :Sm3 = Sm3::new();
		hasher.update(&inputv);
		retv = hasher.finalize().to_vec();
		ecsimple_debug_buffer_trace!(retv.as_ptr(),retv.len(),"sm3 hash");
		Ok(retv)
	}
}

impl std::fmt::Display for ECPrimePubKey {
	fn fmt(&self, f:&mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f,"base {};\npoint {};\n",self.base,self.pubk)
	}
}



#[derive(Clone)]
pub (crate) struct ECPrimePrivateKey {
	base : ECPrimePoint,
	privnum :BigInt,
}

impl Default for ECPrimePrivateKey {
	fn default() -> Self {
		let ov :BigInt = one();
		Self {
			base : ECPrimePoint::default(),
			privnum : ov,
		}
	}
}

impl std::fmt::Display for ECPrimePrivateKey {
	fn fmt(&self, f:&mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f,"base {};\nprivnum {};\n",self.base,self.privnum)
	}
}


impl ECPrimePrivateKey {
	pub (crate) fn new(grp :&ECGroupPrime , privnum :&BigInt) -> ECPrimePrivateKey {
		let b :ECPrimePoint = ECPrimePoint::new(grp);
		ECPrimePrivateKey {
			base : b,
			privnum : privnum.clone(),
		}
	}

	pub (crate) fn generate(grp :&ECGroupPrime) -> ECPrimePrivateKey {
		let b :ECPrimePoint = ECPrimePoint::new(grp);
		let mut privnum :BigInt;
		let zv :BigInt = zero();
		loop {
			privnum = ecsimple_rand_range(&grp.order);
			if privnum != zv {
				break;
			}
		}
		ECPrimePrivateKey {
			base :b,
			privnum : privnum,
		}
	}

	pub fn export_pubkey(&self) -> ECPrimePubKey {
		let ck2 : ECPrimePoint;
		ck2 = self.base.mul_op(&self.privnum,false);
		let x :BigInt = ck2.x();
		let y :BigInt = ck2.y();
		let z :BigInt = one();
		let ck = ck2.set_affine_coordinates(&x,&y,&z).unwrap();
		let retv :ECPrimePubKey = ECPrimePubKey {
			base : self.base.clone(),
			pubk : ck.clone(),
		};
		retv
	}

	pub (crate)  fn to_der(&self,cmprtype :&str,paramenc :&str) -> Result<Vec<u8>,Box<dyn Error>> {
		let pubk :ECPrimePubKey = self.export_pubkey();
		let pubdata :Vec<u8> = pubk.to_bin(cmprtype)?;
		let params :ECPKPARAMETERS;
		let privlen :usize = ((get_max_bits(&self.base.group.order) + 7 ) >> 3) as usize;
		let mut bevecs :Vec<u8>;
		let mut impparams :Asn1ImpSet<ECPKPARAMETERS,0> = Asn1ImpSet::init_asn1();
		let mut asn1pubdata :Asn1BitDataFlag = Asn1BitDataFlag::init_asn1();
		let mut ecprivasn1elem:ECPrivateKeyAsn1Elem = ECPrivateKeyAsn1Elem::init_asn1();
		let mut ecprivasn1 :ECPrivateKeyAsn1 = ECPrivateKeyAsn1::init_asn1();

		params = form_ecpkparameters_prime(&self.base.group,cmprtype,paramenc)?;
		(_,bevecs) = self.privnum.to_bytes_be();
		while bevecs.len() < privlen {
			bevecs.insert(0,0);
		}
		ecprivasn1elem.version.val = 1;
		ecprivasn1elem.privkey.data = bevecs.clone();
		impparams.val.push(params);
		ecprivasn1elem.parameters.val = Some(impparams);
		asn1pubdata.data = pubdata.clone();
		asn1pubdata.flag = 0;
		ecprivasn1elem.pubkey.val.push(asn1pubdata);
		ecprivasn1.elem.val.push(ecprivasn1elem);
		return ecprivasn1.encode_asn1();
	}


	#[allow(unused_assignments)]
	#[allow(non_snake_case)]
	fn setup_sign(&self) -> Result<(BigInt,BigInt),Box<dyn Error>> {
		let mut r :BigInt;
		let mut tmppnt :ECPrimePoint = self.base.clone();
		let zv :BigInt = zero();
		let ov :BigInt = one();
		let mut X :BigInt;
		let e :BigInt;
		tmppnt.set_x(&zv);
		tmppnt.set_y(&zv);
		tmppnt.set_z(&zv);
		let mut k  :BigInt ;
		let blen = get_max_bits(&self.base.group.order);
		ecsimple_log_trace!("tmp.x 0x{:X} tmp.y 0x{:X}, tmp.z 0x{:X}", tmppnt.x(),tmppnt.y(),tmppnt.z());
		ecsimple_log_trace!("order 0x{:X}",self.base.group.order);
		k = ov.clone() << blen;
		loop {
			ecsimple_log_trace!("k 0x{:X}",k);
			k = ecsimple_rand_range(&self.base.group.order);
			ecsimple_log_trace!("k 0x{:X} order 0x{:X} dlen 0x{:x}", k, self.base.group.order,((blen + 7 ) >> 3) as i64);

			ecsimple_log_trace!("group.x 0x{:X} group.y 0x{:X} group.z 0x{:X}", self.base.group.generator.x,self.base.group.generator.y,self.base.group.generator.z);
			tmppnt = self.base.mul_op(&k,false);
			ecsimple_log_trace!("tmp.x 0x{:X} tmp.y 0x{:X} tmp.z 0x{:X}", tmppnt.x(),tmppnt.y(),tmppnt.z());
			X = tmppnt.x();
			r = nmod(&X,&self.base.group.order);
			ecsimple_log_trace!("X 0x{:X} r 0x{:X}", X,r);
			if r != zv {
				break;
			}
		}

		e = self.base.group.order.clone() - ov.clone() - ov.clone();
		ecsimple_log_trace!("k 0x{:X}",k);
		k = k.modpow(&e,&self.base.group.order);
		ecsimple_log_trace!("k 0x{:X} r 0x{:X}",k,r);


		Ok((k,r))
	}

	#[allow(unused_assignments)]
	#[allow(unused_variables)]
	pub fn sign_base(&self,hashnum :&[u8]) -> Result<ECSignature,Box<dyn Error>> {
		let bn :BigInt = BigInt::from_bytes_be(Sign::Plus,hashnum);
		ecsimple_log_trace!("begin sign");
		let mut s :BigInt = zero();
		let mut r :BigInt = zero();
		let kinv :BigInt;
		ecsimple_log_trace!("r 0x{:X} s 0x{:X}",r,s);
		ecsimple_log_trace!("order 0x{:X}", self.base.group.order);

		let realhash = format_bigint_as_order(hashnum,&self.base.group.order);
		ecsimple_log_trace!("dgst 0x{:X}", realhash);
		(kinv,r) = self.setup_sign()?;
		ecsimple_log_trace!("ckinv 0x{:X} r 0x{:X}",kinv,r);
		s = (&realhash + &self.privnum * &r) % &self.base.group.order;
		ecsimple_log_trace!("s 0x{:X}",s);
		s = (&s * &kinv) % &self.base.group.order;
		ecsimple_log_trace!("s 0x{:X}",s);
		ecsimple_log_trace!("r 0x{:X} s 0x{:X}",r,s);
		let retv :ECSignature = ECSignature::new(&r,&s);
		Ok(retv)
	}

	#[allow(non_snake_case)]
	#[allow(unused_variables)]
	pub (crate) fn sign_sm2_base(&self,hashnum :&[u8]) -> Result<ECSignature,Box<dyn Error>> {
		let mut k :BigInt;
		let order :BigInt = self.base.group.order.clone();
		let zv :BigInt = zero();
		let ov :BigInt = one();
		let mut kG :ECPrimePoint;
		let mut r :BigInt;
		let e :BigInt = BigInt::from_bytes_be(Sign::Plus,hashnum);
		let mut x1 :BigInt;
		let mut rk :BigInt;
		let mut s :BigInt;
		let dA :BigInt = self.privnum.clone();
		let e2 :BigInt = order.clone() - ov.clone() - ov.clone();
		let rs :ECSignature;
		let mut tmp :BigInt;
		let mut tmppnt :ECPrimePoint;

		ecsimple_debug_buffer_trace!(hashnum.as_ptr(),hashnum.len(),"dgst");
		loop {
			ecsimple_log_trace!("before generate k");
			k = ecsimple_private_rand_range(&order);
			ecsimple_log_trace!("generate k 0x{:X} order 0x{:X}",k,order);
			if k == zv {
				continue;
			}

			kG = self.base.mul_op(&k,false);
			x1 = kG.x();
			ecsimple_log_trace!("x1 0x{:X}",x1);
			r = (&e + &x1) % &order;
			ecsimple_log_trace!("mod_add(r 0x{:X},e 0x{:X},x1 0x{:X},order 0x{:X})",r,e,x1,order);
			if r == zv {
				continue;
			}

			rk = &r + &k;
			ecsimple_log_trace!("BN_add(rk 0x{:X},r 0x{:X},k 0x{:X})",rk,r,k);

			if rk == order {
				continue;
			}

			s = &dA + &ov;
			s = s.modpow(&e2,&order);
			ecsimple_log_trace!("do_inverse_ord(s 0x{:X},s,order 0x{:X})",s,order);

			tmp = (&dA * &r) % &order;
			ecsimple_log_trace!("BN_mod_mul(tmp 0x{:X},dA 0x{:X},r 0x{:X},order 0x{:X})",tmp,dA,r,order);

			tmp = &k - &tmp;
			ecsimple_log_trace!("BN_sub(tmp 0x{:X},k 0x{:X},tmp)",tmp,k);

			s = (&s * &tmp) % &order;
			if s < zv {
				s += &order;
			}
			ecsimple_log_trace!("BN_mod_mul(s 0x{:X},s,tmp 0x{:X},order 0x{:X})",s,tmp,order);

			if s != zv {
				break;
			}
		}

		ecsimple_log_trace!("final r 0x{:X} s 0x{:X}",r,s);
		rs = ECSignature::new(&r,&s);
		Ok(rs)
	}

	pub (crate) fn get_sm3_hashcode(&self, idv :&[u8]) -> Result<Vec<u8>,Box<dyn Error>> {
		let pubk :ECPrimePubKey = self.export_pubkey();
		return pubk.get_sm3_hashcode(idv);
	}
}


pub (crate) fn extract_compressed_y_prime(grp :&ECGroupPrime, x_ :&BigInt, ybit :u8) -> Result<BigInt,Box<dyn Error>> {
	let b = ECPrimePoint::new(grp);
	let field :BigInt = b.group.p.clone();
	let x :BigInt = nmod(&x_,&grp.p);
	ecsimple_log_trace!("nnmod(x 0x{:X},x_ 0x{:X},group.field 0x{:X})", x,x_,grp.p);
	let mut y :BigInt;
	let mut tmp2 :BigInt;
	let mut tmp1 :BigInt;
	let mut kbit :i32;
	let zv :BigInt = zero();
	tmp2 = (x_.clone() * x_.clone()) % &field;
	ecsimple_log_trace!("mod_sqr(tmp2 0x{:X},x_ 0x{:X},group.field 0x{:X})",tmp2,x_,grp.p);
	tmp1 = (tmp2.clone() * x_.clone()) % &field;
	ecsimple_log_trace!("mod_mul(tmp1 0x{:X},tmp2 0x{:X},x_ 0x{:X},group.field 0x{:X})",tmp1,tmp2,x_,field);
	if grp.is_minus3 {
		tmp2 = b.lshift1_mod_quick(&x,&field);
		ecsimple_log_trace!("lshift1_mod_quick(tmp2 0x{:X},x 0x{:X},group.field 0x{:X})",tmp2,x,field);
		tmp2 = b.add_mod_quick(&tmp2,&x,&field);
		ecsimple_log_trace!("add_mod_quick(tmp2 0x{:X},tmp2,x 0x{:X},group.field 0x{:X})",tmp2,x,field);
		tmp1 = b.sub_mod_quick(&tmp1,&tmp2,&field);
		ecsimple_log_trace!("sub_mod_quick(tmp1 0x{:X},tmp1,tmp2 0x{:X},group.field 0x{:X})",tmp1,tmp2,field);
	} else {
		tmp2 = b.field_decode(&grp.a);
		tmp2 = (tmp2.clone() * x.clone()) % &field;
		ecsimple_log_trace!("mod_mul(tmp2 0x{:X},tmp2,x 0x{:X},group.field 0x{:X})",tmp2,x,field);

		tmp1 = b.add_mod_quick(&tmp1,&tmp2,&field);
		ecsimple_log_trace!("add_mod_quick(tmp1 0x{:X},tmp1,tmp2 0x{:X},group.field 0x{:X})",tmp1,tmp2,field);
	}

	tmp2 = b.field_decode(&grp.b);
	tmp1 = b.add_mod_quick(&tmp1,&tmp2,&field);
	ecsimple_log_trace!("add_mod_quick(tmp1 0x{:X},tmp1,tmp2 0x{:X},group.field 0x{:X})",tmp1,tmp2,field);

	y = mod_sqrt(&tmp1,&field)?;
	ecsimple_log_trace!("mod_sqr(y 0x{:X},tmp1 0x{:X},group.field 0x{:X})",y,tmp1,field);
	kbit = get_bit_set(&y,0);
	if kbit != ybit as i32 {
		if y == zv {
			ecsimple_new_error!{EcKeyError,"not valid y 0x{:X}",y}
		}
		y = &field - &y;
		ecsimple_log_trace!("usub(y 0x{:X},group.field 0x{:X},y)",y,field);
	}
	kbit = get_bit_set(&y,0);
	if kbit != ybit as i32 {
		ecsimple_new_error!{EcKeyError,"y 0x{:X} not valid for bit",y}
	}

	Ok(y)
}

pub (crate) fn extract_compressed_y_gf2m(grp :&ECGroupBnGf2m,x_ :&BigInt,ybit :u8) -> Result<BigInt,Box<dyn Error>> {
	let b = ECGf2mPoint::new(grp);
	let xb :BnGf2m = BnGf2m::new_from_bigint(&x_);
	let field :BnGf2m = BnGf2m::new_from_bigint(&b.group.p);
	let x :BnGf2m = &xb % &field;
	let y :BigInt;
	let mut yn :BnGf2m;
	let mut tmp :BnGf2m;
	let z :BnGf2m;
	let z0 :u8;
	ecsimple_log_trace!("x 0x{:X} = x_ 0x{:X} % group->field 0x{:X}",x,x_,field);
	if x.is_zero() {
		let yn = &b.group.b.mul_op(&b.group.b).mod_op(&field);
		y = yn.to_bigint();
		ecsimple_log_trace!("y 0x{:X} = group->b 0x{:X} ^ 2 % field 0x{:X}",y,b.group.b,field);
	} else {
		tmp = b.field_sqr(&x);
		tmp = b.field_div(&b.group.b,&tmp)?;
		tmp = tmp.add_op(&b.group.a);
		ecsimple_log_trace!("tmp 0x{:X} group->a 0x{:X}",tmp,b.group.a);
		tmp = tmp.add_op(&x);
		ecsimple_log_trace!("tmp 0x{:X} x 0x{:X}",tmp,x);
		z = tmp.sqrt_quad_op(&field)?;
		ecsimple_log_trace!("z 0x{:X}",z);
		if z.is_odd() {
			z0 = 1;
		} else {
			z0 = 0;
		}
		yn = b.field_mul(&x,&z);
		if z0 != ybit {
			yn = yn.add_op(&x);
			ecsimple_log_trace!("y 0x{:X} x 0x{:X}",yn,x);
		}
		y = yn.to_bigint();
	}
	Ok(y)
}

pub (crate) fn get_group_from_ecpkparameters_der(ecpkparams :&ECPKPARAMETERS) -> Result<ECGroup,Box<dyn Error>> {
	let curveparams :X9_62_CURVEElem;
	let ov :BigInt = one();
	let retgrp :ECGroup;
	let mut tmpp :BigInt;
	let mut bevecs :Vec<u8>;
	let x :BigInt;
	let y :BigInt;
	let ybit :u8;
	let fieldlen : usize;
	if ecpkparams.itype == 0 {
		/*now to get the oid*/
		let oid :String = ecpkparams.named_curve.get_value();
		let ecname = ecc_get_name_from_oid(&oid)?;
		retgrp = ecc_get_curve_group(&ecname)?;
		ecsimple_log_trace!("{}",retgrp);
		return Ok(retgrp);
	} else if ecpkparams.itype == 1 {
		let paramselem :ECPARAMETERSElem;
		if ecpkparams.parameters.elem.val.len() != 1 {
			ecsimple_new_error!{EcKeyError,"params elem {} != 1",ecpkparams.parameters.elem.val.len()}
		}
		paramselem = ecpkparams.parameters.elem.val[0].clone();
		let fieldid :X9_62_FIELDIDElem ;

		if paramselem.curve.elem.val.len() != 1 {
			ecsimple_new_error!{EcKeyError,"curve {} != 1", paramselem.curve.elem.val.len()}
		}
		curveparams = paramselem.curve.elem.val[0].clone();

		if paramselem.fieldID.elem.val.len() != 1 {
			ecsimple_new_error!{EcKeyError,"fieldID elem {} != 1 ", paramselem.fieldID.elem.val.len()}
		}
		fieldid = paramselem.fieldID.elem.val[0].clone();
		if fieldid.fieldType.val.get_value() == EC_PRIME_GROUP_TYPE_OID {
			let mut primegrp :ECGroupPrime = ECGroupPrime::default();
			let montv :MontNum;
			let tmpa :BigInt;
			/*secp112r1*/
			/*
			v8 = Vec::from_hex("DB7C2ABF62E35E668076BEAD208B").unwrap();
			p = BigInt::from_bytes_be(Sign::Plus,&v8);
			bngrp.p = p.clone();
			montv = MontNum::new(&bngrp.p).unwrap();
			tmpp = p.clone();
			v8 = Vec::from_hex("DB7C2ABF62E35E668076BEAD2088").unwrap();
			p = BigInt::from_bytes_be(Sign::Plus,&v8);
			tmpa = p.clone();
			bngrp.a = montv.mont_to(&p);
			v8 = Vec::from_hex("659EF8BA043916EEDE8911702B22").unwrap();
			p = BigInt::from_bytes_be(Sign::Plus,&v8);
			bngrp.b = montv.mont_to(&p);
			v8 = Vec::from_hex("09487239995A5EE76B55F9C2F098").unwrap();
			p = BigInt::from_bytes_be(Sign::Plus,&v8);
			bngrp.generator.x = montv.mont_to(&p);
			v8 = Vec::from_hex("A89CE5AF8724C0A23E0E0FF77500").unwrap();
			p = BigInt::from_bytes_be(Sign::Plus,&v8);
			bngrp.generator.y = montv.mont_to(&p);
			bngrp.generator.z = montv.mont_to(&ov);

			v8 = Vec::from_hex("DB7C2ABF62E35E7628DFAC6561C5").unwrap();
			p = BigInt::from_bytes_be(Sign::Plus,&v8);
			bngrp.order = p.clone();
			bngrp.cofactor = ov.clone();
			bngrp.curvename = SECP112r1_NAME.to_string();

			//ecsimple_log_trace!("tmpp 0x{:X} tmpa 0x{:X}",tmpp,tmpa);
			if tmpp == (tmpa.clone() + ov.clone() + ov.clone() + ov.clone()) {
				bngrp.is_minus3 = true;
				//ecsimple_log_trace!("{} is_minus3 true",SECP112r1_NAME);
			} else {
				bngrp.is_minus3 = false;
				//ecsimple_log_trace!("{} is_minus3 false",SECP112r1_NAME);
			}
			retv.insert(SECP112r1_NAME.to_string(),bngrp.clone());
			*/
			bevecs = fieldid.prime.val.to_bytes_be();
			primegrp.p = BigInt::from_bytes_be(Sign::Plus,&bevecs);
			montv = MontNum::new(&primegrp.p).unwrap();
			bevecs = curveparams.a.data.clone();
			tmpp = BigInt::from_bytes_be(Sign::Plus,&bevecs);
			tmpa = tmpp.clone();
			primegrp.a = montv.mont_to(&tmpp);
			bevecs = curveparams.b.data.clone();
			tmpp = BigInt::from_bytes_be(Sign::Plus,&bevecs);
			primegrp.b = montv.mont_to(&tmpp);

			primegrp.seed = zero();
			primegrp.seed_len = 0;
			if curveparams.seed.val.is_some() {
				let bn :Asn1BitDataFlag = curveparams.seed.val.as_ref().unwrap().clone();
				bevecs = bn.data.clone();
				primegrp.seed = BigInt::from_bytes_be(Sign::Plus,&bevecs);
				primegrp.seed_len = bevecs.len();
			}

			bevecs = paramselem.order.val.to_bytes_be();
			tmpp = BigInt::from_bytes_be(Sign::Plus,&bevecs);
			primegrp.order = tmpp.clone();


			if paramselem.cofactor.val.is_none() {
				primegrp.cofactor = ov.clone();
			} else {
				bevecs = paramselem.cofactor.val.as_ref().unwrap().clone().val.to_bytes_be();
				primegrp.cofactor = BigInt::from_bytes_be(Sign::Plus,&bevecs);
			}

			if primegrp.p == (tmpa.clone() + ov.clone() + ov.clone() + ov.clone() ) {
				primegrp.is_minus3 = true;
			} else {
				primegrp.is_minus3 = false;
			}


			bevecs = paramselem.base.data.clone();
			ybit = bevecs[0] & EC_CODE_YBIT;
			let degr :i64 = primegrp.degree();
			fieldlen = ((degr + 7) >> 3) as usize;
			if (bevecs[0] & EC_CODE_MASK)==  EC_CODE_COMPRESSED {
				if bevecs.len() != (1 + fieldlen) {
					ecsimple_new_error!{EcKeyError,"vecs [0x{:x}] != 1 + 0x{:x}",bevecs.len(),fieldlen }
				}
				x = BigInt::from_bytes_be(Sign::Plus,&bevecs[1..(1+fieldlen)]);
				y = extract_compressed_y_prime(&primegrp,&x,ybit)?;
			} else if (bevecs[0] & EC_CODE_MASK) == EC_CODE_UNCOMPRESSED {
				if bevecs.len() != (1 + 2 * fieldlen) {
					ecsimple_new_error!{EcKeyError,"vecs [0x{:x}] != 1 + 0x{:x} * 2",bevecs.len(),fieldlen }	
				}
				x = BigInt::from_bytes_be(Sign::Plus,&bevecs[1..(1+fieldlen)]);
				y = BigInt::from_bytes_be(Sign::Plus,&bevecs[(fieldlen+1)..(2*fieldlen+1)]);
			} else if (bevecs[0] & EC_CODE_MASK) == EC_CODE_HYBRID {
				if bevecs.len() != (1 + 2 * fieldlen) {
					ecsimple_new_error!{EcKeyError,"vecs [0x{:x}] != 1 + 0x{:x} * 2",bevecs.len(),fieldlen }	
				}
				x = BigInt::from_bytes_be(Sign::Plus,&bevecs[1..(1+fieldlen)]);
				y = BigInt::from_bytes_be(Sign::Plus,&bevecs[(fieldlen+1)..(2*fieldlen+1)]);
				if x == zero() && ybit != 0 {
					ecsimple_new_error!{EcKeyError,"x == 0 and ybit set"}
				}
			} else {
				ecsimple_new_error!{EcKeyError,"not supported type [0x{:02x}]", bevecs[0]}
			}

			primegrp.generator.x = montv.mont_to(&x);
			primegrp.generator.y = montv.mont_to(&y);
			primegrp.generator.z = montv.mont_to(&ov);
			primegrp.curvename = "".to_string();

			ecsimple_log_trace!("primegrp\n{}",primegrp);
			retgrp = ECGroup::new_prime_group(&primegrp);
			return Ok(retgrp);
		} else if fieldid.fieldType.val.get_value() == EC_GF2M_GROUP_TYPE_OID {
			let mut bngrp :ECGroupBnGf2m = ECGroupBnGf2m::default();
			let x962elem : X9_62_CHARACTERISTIC_TWO_ELEM;
			let ppbasis :X9_62_PENTANOMIALELem;
			let mut kval :i32;
			/*sect113r1*/
			/*
			v8 = Vec::from_hex("0800000000000000000000000000000000000000C9").unwrap();
			p = BigInt::from_bytes_be(Sign::Plus,&v8);
			bngrp.p = p.clone();
			v8 = Vec::from_hex("07b6882caaefa84f9554ff8428bd88e246d2782ae2").unwrap();
			p = BigInt::from_bytes_be(Sign::Plus,&v8);
			bngrp.a = BnGf2m::new_from_bigint(&p);
			v8 = Vec::from_hex("0713612dcddcb40aab946bda29ca91f73af958afd9").unwrap();
			p = BigInt::from_bytes_be(Sign::Plus,&v8);
			bngrp.b = BnGf2m::new_from_bigint(&p);
			v8 = Vec::from_hex("0369979697ab43897789566789567f787a7876a654").unwrap();
			p = BigInt::from_bytes_be(Sign::Plus,&v8);
			bngrp.generator.x = BnGf2m::new_from_bigint(&p);
			v8 = Vec::from_hex("00435edb42efafb2989d51fefce3c80988f41ff883").unwrap();
			p = BigInt::from_bytes_be(Sign::Plus,&v8);
			bngrp.generator.y = BnGf2m::new_from_bigint(&p);
			bngrp.generator.z = BnGf2m::one();

			v8 = Vec::from_hex("03ffffffffffffffffffff48aab689c29ca710279b").unwrap();
			p = BigInt::from_bytes_be(Sign::Plus,&v8);
			bngrp.order = p.clone();
			bngrp.cofactor = &ov + &ov;
			bngrp.curvename = SECT163r1_NAME.to_string();

			retv.insert(SECT163r1_NAME.to_string(),bngrp.clone());
			*/
			if fieldid.char_two.elem.val.len() != 1 {
				ecsimple_new_error!{EcKeyError,"char_two elem {} != 1",fieldid.char_two.elem.val.len()}
			}
			x962elem =  fieldid.char_two.elem.val[0].clone();
			let oidstr :String = x962elem.elemchoice.otype.val.get_value();
			if oidstr != EC_PP_BASIS_OID && oidstr != EC_TP_BASIS_OID && oidstr != EC_ON_BASIS_OID {
				ecsimple_new_error!{EcKeyError,"otype [{}] not supported", oidstr}
			}

			if oidstr == EC_PP_BASIS_OID {
				if x962elem.elemchoice.ppBasis.elem.val.len() != 1 {
					ecsimple_new_error!{EcKeyError,"ppBasis len {} != 1",x962elem.elemchoice.ppBasis.elem.val.len()}
				}
				ppbasis = x962elem.elemchoice.ppBasis.elem.val[0].clone();

				tmpp = one();
				tmpp |= ov.clone() << x962elem.m.val;
				if ppbasis.k1.val != 0 {
					kval = ppbasis.k1.val as i32;
					tmpp |= ov.clone() << kval;				
				}
				if ppbasis.k2.val != 0 {
					kval = ppbasis.k2.val as i32;
					tmpp |= ov.clone() << kval;
				}
				if ppbasis.k3.val != 0 {
					kval = ppbasis.k3.val as i32;
					tmpp |= ov.clone() << kval;
				}
				bngrp.p = tmpp.clone();				
			} else if oidstr == EC_TP_BASIS_OID {
				tmpp = one();
				tmpp |= ov.clone() << x962elem.m.val;
				let mut shifti :u64 = 0;
				bevecs = x962elem.elemchoice.tpBasis.val.to_bytes_be();
				let mut idx :usize = 0;
				while idx < bevecs.len() {
					shifti |= (bevecs[idx] as u64) << (idx * 8);
					idx += 1;
				}
				tmpp |= ov.clone() << shifti;
				bngrp.p = tmpp.clone();
			}

			bevecs = curveparams.a.data.clone();
			tmpp = BigInt::from_bytes_be(Sign::Plus,&bevecs);
			bngrp.a = BnGf2m::new_from_bigint(&tmpp);

			bevecs = curveparams.b.data.clone();
			tmpp = BigInt::from_bytes_be(Sign::Plus,&bevecs);
			bngrp.b = BnGf2m::new_from_bigint(&tmpp);

			bngrp.seed = zero();
			bngrp.seed_len = 0;
			if curveparams.seed.val.is_some() {
				let bn :Asn1BitDataFlag = curveparams.seed.val.as_ref().unwrap().clone();
				bevecs = bn.data.clone();
				bngrp.seed = BigInt::from_bytes_be(Sign::Plus,&bevecs);
				bngrp.seed_len = bevecs.len();
			}

			bevecs = paramselem.order.val.to_bytes_be();
			tmpp = BigInt::from_bytes_be(Sign::Plus,&bevecs);
			bngrp.order = tmpp.clone();
			if paramselem.cofactor.val.is_none() {
				bngrp.cofactor = ov.clone();
			} else {
				bevecs = paramselem.cofactor.val.as_ref().unwrap().clone().val.to_bytes_be();
				bngrp.cofactor = BigInt::from_bytes_be(Sign::Plus,&bevecs);
			}



			bevecs = paramselem.base.data.clone();
			ybit = bevecs[0] & EC_CODE_YBIT;
			let degr :i64 = bngrp.degree();
			fieldlen = ((degr + 7) >> 3) as usize;
			if (bevecs[0] & EC_CODE_MASK)==  EC_CODE_COMPRESSED {
				if bevecs.len() != (1 + fieldlen) {
					ecsimple_new_error!{EcKeyError,"vecs [0x{:x}] != 1 + 0x{:x}",bevecs.len(),fieldlen }
				}
				x = BigInt::from_bytes_be(Sign::Plus,&bevecs[1..(1+fieldlen)]);
				y = extract_compressed_y_gf2m(&bngrp,&x,ybit)?;
			} else if (bevecs[0] & EC_CODE_MASK) == EC_CODE_UNCOMPRESSED {
				if bevecs.len() != (1 + 2 * fieldlen) {
					ecsimple_new_error!{EcKeyError,"vecs [0x{:x}] != 1 + 0x{:x} * 2",bevecs.len(),fieldlen }	
				}
				x = BigInt::from_bytes_be(Sign::Plus,&bevecs[1..(1+fieldlen)]);
				y = BigInt::from_bytes_be(Sign::Plus,&bevecs[(fieldlen+1)..(2*fieldlen+1)]);
			} else if (bevecs[0] & EC_CODE_MASK) == EC_CODE_HYBRID {
				if bevecs.len() != (1 + 2 * fieldlen) {
					ecsimple_new_error!{EcKeyError,"vecs [0x{:x}] != 1 + 0x{:x} * 2",bevecs.len(),fieldlen }	
				}
				x = BigInt::from_bytes_be(Sign::Plus,&bevecs[1..(1+fieldlen)]);
				y = BigInt::from_bytes_be(Sign::Plus,&bevecs[(fieldlen+1)..(2*fieldlen+1)]);
				if x == zero() && ybit != 0 {
					ecsimple_new_error!{EcKeyError,"x == 0 and ybit set"}
				}
			} else {
				ecsimple_new_error!{EcKeyError,"not supported type [0x{:02x}]", bevecs[0]}
			}

			bngrp.generator.x = BnGf2m::new_from_bigint(&x);
			bngrp.generator.y = BnGf2m::new_from_bigint(&y);
			bngrp.generator.z = BnGf2m::one();
			ecsimple_log_trace!("bngrp\n{}",bngrp);
			retgrp = ECGroup::new_bn_group(&bngrp);
			return Ok(retgrp);
		} 
		ecsimple_new_error!{EcKeyError,"not supported oid fieldType [{}]",fieldid.fieldType.val.get_value()}

	}
	ecsimple_new_error!{EcKeyError,"not supported type [{}]",ecpkparams.itype}	
}

pub (crate) fn get_group_from_public_der(pubkey :&ECPublicKeyAsn1) -> Result<ECGroup,Box<dyn Error>> {
	if pubkey.elem.val.len() != 1 {
		ecsimple_new_error!{EcKeyError,"ECPublicKeyAsn1.elem.val.len() {} != 1",pubkey.elem.val.len()}
	}
	let pubkeyelem :ECPublicKeyAsn1Elem = pubkey.elem.val[0].clone();
	if pubkeyelem.packed.elem.val.len() != 1 {
		ecsimple_new_error!{EcKeyError,"ECPublicKeyAsn1Elem.packed.elem.val.len() {} != 1",pubkeyelem.packed.elem.val.len()}
	}
	let packedelem :ECPublicKeyPackElem = pubkeyelem.packed.elem.val[0].clone();
	let typef :String = packedelem.typef.get_value();
	if typef != EC_PUBLIC_KEY_OID {
		if typef != SM2_OID {
			ecsimple_new_error!{EcKeyError,"typef [{}] != EC_PUBLIC_KEY_OID[{}]",typef,EC_PUBLIC_KEY_OID}	
		}
		/*now we should give the */	
		return ecc_get_curve_group(SM2_NAME);
	}
	return get_group_from_ecpkparameters_der(&packedelem.parameters);
}


#[derive(Clone)]
pub struct ECPublicKey {
	pub (crate) bnkey :Option<ECGf2mPubKey>,
	pub (crate) primekey :Option<ECPrimePubKey>,
}

impl Default for ECPublicKey {
	fn default() -> Self {
		Self {
			bnkey : None,
			primekey : None,
		}
	}
}

impl ECPublicKey {
	pub fn new(grp :&ECGroup,x :&BigInt,y :&BigInt) -> ECPublicKey {
		let retv :ECPublicKey;
		if grp.is_bn_group() {
			retv =  ECPublicKey{
				bnkey : Some(ECGf2mPubKey::new(&grp.get_bn_group(),x,y)),
				primekey : None,
			};
		} else {
			retv = ECPublicKey {
				bnkey : None,
				primekey : Some(ECPrimePubKey::new(&grp.get_prime_group(),x,y)),
			} ;
		}
		return retv;
	}

	pub fn from_der(dercode :&[u8]) -> Result<ECPublicKey, Box<dyn Error>> {
		let mut pubkeyasn1 :ECPublicKeyAsn1 = ECPublicKeyAsn1::init_asn1();
		let _ = pubkeyasn1.decode_asn1(dercode)?;
		let grp :ECGroup = get_group_from_public_der(&pubkeyasn1)?;
		let pubkeyasn1elem :ECPublicKeyAsn1Elem = pubkeyasn1.elem.val[0].clone();
		return Self::from_bin(&grp,&pubkeyasn1elem.pubdata.data);
	}

	pub fn to_der(&self,cmprtype :&str,paramenc :&str) -> Result<Vec<u8>,Box<dyn Error>> {
		let retv :Vec<u8>;
		if self.is_bn_key() {
			retv= self.get_bn_key().to_der(cmprtype,paramenc)?;
		} else {
			retv = self.get_prime_key().to_der(cmprtype,paramenc)?;
		} 
		Ok(retv)
	}

	pub fn to_bin(&self,cmprtype :&str) -> Result<Vec<u8>,Box<dyn Error>> {
		let retv :Vec<u8>;
		if self.is_bn_key() {
			retv= self.get_bn_key().to_bin(cmprtype)?;
		} else {
			retv = self.get_prime_key().to_bin(cmprtype)?;
		} 
		Ok(retv)

	}

	pub fn is_sm2(&self) -> bool {
		if self.is_bn_key() {
			return false;
		}
		let curpriv :ECPrimePubKey = self.primekey.as_ref().unwrap().clone();
		let curgrp :ECGroupPrime = curpriv.base.group.clone();
		let sm2grp :ECGroup ;
		let ores = ecc_get_curve_group(SM2_NAME);
		if ores.is_err() {
			return false;
		}
		sm2grp = ores.unwrap();
		let sm2primegrp = sm2grp.get_prime_group();
		if curgrp != sm2primegrp {
			return false;
		}
		return true;
	}


	pub fn from_bin(grp :&ECGroup, dercode :&[u8]) -> Result<Self,Box<dyn Error>> {
		let retv :ECPublicKey;
		if grp.is_bn_group() {
			let bnkey : ECGf2mPubKey = ECGf2mPubKey::from_bin(&grp.get_bn_group(),dercode)?;
			retv = ECPublicKey {
				bnkey : Some(bnkey),
				primekey : None,
			};
		} else {
			let primekey : ECPrimePubKey = ECPrimePubKey::from_bin(&grp.get_prime_group(),dercode)?;
			retv = ECPublicKey {
				bnkey : None,
				primekey : Some(primekey),
			};
		} 
		Ok(retv)
	}

	fn is_bn_key(&self) -> bool {
		if self.bnkey.is_some() {
			return true;
		}
		return false;
	}

	fn is_prime_key(&self) -> bool {
		if self.primekey.is_some() {
			return true;
		}
		return false;
	}

	fn get_bn_key(&self) -> ECGf2mPubKey {
		let mut retv :ECGf2mPubKey = ECGf2mPubKey::default();
		if self.is_bn_key() {
			retv = self.bnkey.as_ref().unwrap().clone();
		}
		return retv;
	}

	fn get_prime_key(&self) -> ECPrimePubKey {
		let mut retv :ECPrimePubKey = ECPrimePubKey::default();
		if self.is_prime_key() {
			retv = self.primekey.as_ref().unwrap().clone();
		}
		return retv;
	}

	pub fn verify_base(&self,sig :&ECSignature, hashnum :&[u8]) -> Result<bool,Box<dyn Error>> {
		if self.is_bn_key() {
			return self.get_bn_key().verify_base(sig,hashnum);
		}  else if self.is_prime_key() {
			return self.get_prime_key().verify_base(sig,hashnum);
		}
		ecsimple_new_error!{EcKeyError,"not supported public key"}
	}

	pub fn verify_sm2_base(&self,sig :&ECSignature,hashnum :&[u8]) -> Result<bool,Box<dyn Error>> {
		if self.is_sm2() {
			return self.get_prime_key().verify_sm2_base(sig,hashnum);
		}
		ecsimple_new_error!{EcKeyError,"not support sm2"}
	}

	pub fn get_sm3_hashcode(&self,idv :&[u8]) -> Result<Vec<u8>,Box<dyn Error>> {
		if self.is_sm2() {
			return self.get_prime_key().get_sm3_hashcode(idv);
		}
		ecsimple_new_error!{EcKeyError,"not support sm2"}
	}
}

impl std::fmt::Display for ECPublicKey {
	fn fmt(&self, f:&mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		if self.is_prime_key() {
			return self.get_prime_key().fmt(f);
		}
		return self.get_bn_key().fmt(f);		
	}
}

pub (crate) fn get_group_from_private_pk8_der(_privkey :&ECPrivateKeyAsn1,pk8 :&Asn1Pkcs8PrivKeyInfo) -> Result<ECGroup,Box<dyn Error>> {
	if pk8.elem.val.len() != 1 {
		ecsimple_new_error!{EcKeyError,"Asn1Pkcs8PrivKeyInfo elem {} != 1",pk8.elem.val.len()}
	}
	let pk8elem :Asn1Pkcs8PrivKeyInfoElem = pk8.elem.val[0].clone();
	if pk8elem.version.val != 0 {
		ecsimple_new_error!{EcKeyError,"Asn1Pkcs8PrivKeyInfo version {} != 0",pk8elem.version.val}
	}
	if pk8elem.pkeyalg.elem.val.len() != 1 {
		ecsimple_new_error!{EcKeyError,"Asn1X509Algor elem {} != 1" ,pk8elem.pkeyalg.elem.val.len()}
	}
	let algoelem :Asn1X509AlgorElem = pk8elem.pkeyalg.elem.val[0].clone();
	let oid :String = algoelem.algorithm.get_value();
	let ecname :String = ecc_get_name_from_oid(&oid)?;
	return ecc_get_curve_group(&ecname);
}

pub (crate) fn get_group_from_private_der(privkey :&ECPrivateKeyAsn1) -> Result<ECGroup,Box<dyn Error>> {
	if privkey.elem.val.len() != 1 {
		ecsimple_new_error!{EcKeyError,"ECPrivateKeyAsn1.elem.val.len() {} != 1",privkey.elem.val.len()}
	}
	let privkeyelem :ECPrivateKeyAsn1Elem = privkey.elem.val[0].clone();
	if privkeyelem.parameters.val.is_none() {
		ecsimple_new_error!{EcKeyError,"ECPrivateKeyAsn1Elem parameters none"}
	}
	let ecpkparamsset :Asn1ImpSet<ECPKPARAMETERS,0> = privkeyelem.parameters.val.as_ref().unwrap().clone();
	if ecpkparamsset.val.len() != 1 {
		ecsimple_new_error!{EcKeyError,"paramters impset len {} != 1", ecpkparamsset.val.len()}
	}
	let ecpkparams :ECPKPARAMETERS = ecpkparamsset.val[0].clone();
	return get_group_from_ecpkparameters_der(&ecpkparams);
}


#[derive(Clone)]
pub struct ECPrivateKey {
	pub (crate) bnkey :Option<ECGf2mPrivateKey>,
	pub (crate) primekey :Option<ECPrimePrivateKey>,
}

impl Default for ECPrivateKey {
	fn default() -> Self {
		Self {
			bnkey : None,
			primekey : None,
		}
	}
}


impl ECPrivateKey {
	pub fn from_der(dercode :&[u8]) -> Result<ECPrivateKey,Box<dyn Error>> {
		let mut privkey :ECPrivateKeyAsn1 = ECPrivateKeyAsn1::init_asn1();
		let ores = privkey.decode_asn1(&dercode);
		let mut setpkinfo8 :bool = false;
		let mut pk8info :Asn1Pkcs8PrivKeyInfo = Asn1Pkcs8PrivKeyInfo::init_asn1();
		if ores.is_err() {
			let _ = pk8info.decode_asn1(&dercode)?;
			if pk8info.elem.val.len() != 1 {
				ecsimple_new_error!{EcKeyError,"pk8info elem val len {} != 1",pk8info.elem.val.len()}
			}
			let _ = privkey.decode_asn1(&pk8info.elem.val[0].pkey.data)?;
			setpkinfo8 = true;
		}
		if privkey.elem.val.len() != 1 {
			ecsimple_new_error!{EcKeyError,"privkey elem val len {} != 1",privkey.elem.val.len()}
		}
		let privkeyelem :ECPrivateKeyAsn1Elem = privkey.elem.val[0].clone();

		let grp :ECGroup ;
		if setpkinfo8 {
			grp = get_group_from_private_pk8_der(&privkey,&pk8info)?;
		} else {
			grp = get_group_from_private_der(&privkey)?;
		}
		
		if privkeyelem.version.val != 1 {
			ecsimple_new_error!{EcKeyError,"privkey version {} != 1",privkeyelem.version.val}
		}
		let privdata :Vec<u8> = privkeyelem.privkey.data.clone();
		let privnum :BigInt = BigInt::from_bytes_be(Sign::Plus,&privdata);
		let retv :ECPrivateKey = ECPrivateKey::new(&grp,&privnum);
		return Ok(retv);
	}

	pub fn new(grp :&ECGroup , privnum :&BigInt) -> ECPrivateKey {
		let retv :ECPrivateKey;
		if grp.is_bn_group() {
			retv = ECPrivateKey {
				bnkey : Some(ECGf2mPrivateKey::new(&grp.get_bn_group(),privnum)),
				primekey : None,
			};
		} else {
			retv = ECPrivateKey {
				bnkey : None,
				primekey : Some(ECPrimePrivateKey::new(&grp.get_prime_group(),privnum)),
			};
		}
		return retv;
	}

	pub fn generate(grp :&ECGroup) -> ECPrivateKey {
		let retv :ECPrivateKey;
		if grp.is_bn_group() {
			retv = ECPrivateKey {
				bnkey : Some(ECGf2mPrivateKey::generate(&grp.get_bn_group())),
				primekey : None,
			};
		} else {
			retv = ECPrivateKey {
				bnkey : None,
				primekey : Some(ECPrimePrivateKey::generate(&grp.get_prime_group())),
			};
		}
		return retv;
	}

	pub fn export_pubkey(&self) -> ECPublicKey {
		let mut retv :ECPublicKey = ECPublicKey::default();
		if self.is_prime_key() {
			let pubk = self.get_prime_key().export_pubkey();
			retv.primekey = Some(pubk);
		} else if self.is_bn_key() {
			let pubk = self.get_bn_key().export_pubkey();
			retv.bnkey = Some(pubk);
		}
		return retv;
	}

	fn is_bn_key(&self) -> bool {
		if self.bnkey.is_some() {
			return true;
		}
		return false;
	}

	fn is_prime_key(&self) -> bool {
		if self.primekey.is_some() {
			return true;
		}
		return false;
	}

	pub fn is_sm2(&self) -> bool {
		if self.is_bn_key() {
			return false;
		}
		let curpriv :ECPrimePrivateKey = self.primekey.as_ref().unwrap().clone();
		let curgrp :ECGroupPrime = curpriv.base.group.clone();
		let sm2grp :ECGroup ;
		let ores = ecc_get_curve_group(SM2_NAME);
		if ores.is_err() {
			return false;
		}
		sm2grp = ores.unwrap();
		let sm2primegrp = sm2grp.get_prime_group();
		if curgrp != sm2primegrp {
			return false;
		}
		return true;
	}

	fn get_bn_key(&self) -> ECGf2mPrivateKey {
		let mut retv : ECGf2mPrivateKey = ECGf2mPrivateKey::default();
		if self.is_bn_key() {
			retv = self.bnkey.as_ref().unwrap().clone();
		}
		return retv;
	}

	fn get_prime_key(&self) -> ECPrimePrivateKey {
		let mut retv : ECPrimePrivateKey = ECPrimePrivateKey::default();
		if self.is_prime_key() {
			retv = self.primekey.as_ref().unwrap().clone();
		}
		return retv;
	}


	pub fn sign_base(&self,hashnum :&[u8]) -> Result<ECSignature,Box<dyn Error>> {
		if self.is_bn_key() {
			return self.get_bn_key().sign_base(hashnum);
		} else if self.is_prime_key() {
			return self.get_prime_key().sign_base(hashnum);
		}
		ecsimple_new_error!{EcKeyError,"not supported private key"}
	}

	pub fn sign_sm2_base(&self,hashnum :&[u8]) -> Result<ECSignature,Box<dyn Error>> {
		if self.is_sm2() {
			return self.get_prime_key().sign_sm2_base(hashnum);
		}
		ecsimple_new_error!{EcKeyError,"not SM2 to support"}
	}

	pub fn to_der(&self,cmprtype :&str,paramenc :&str) -> Result<Vec<u8>,Box<dyn Error>> {
		if self.is_bn_key() {
			return self.get_bn_key().to_der(cmprtype,paramenc);
		} else if self.is_prime_key() {
			return self.get_prime_key().to_der(cmprtype,paramenc);
		}
		ecsimple_new_error!{EcKeyError,"not supported private key"}		
	}

	pub fn get_sm3_hashcode(&self,idv :&[u8]) -> Result<Vec<u8>,Box<dyn Error>> {
		if self.is_bn_key() {
			ecsimple_new_error!{EcKeyError,"not support sm3"}
		}
		return self.get_prime_key().get_sm3_hashcode(idv);
	}
}

impl std::fmt::Display for ECPrivateKey {
	fn fmt(&self, f:&mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		if self.is_prime_key() {
			return self.get_prime_key().fmt(f);
		}
		return self.get_bn_key().fmt(f);		
	}
}


pub fn to_der_sm2(incode :&[u8]) -> Result<Vec<u8>,Box<dyn Error>> {
	let mut pk8info :Asn1Pkcs8PrivKeyInfo = Asn1Pkcs8PrivKeyInfo::init_asn1();
	let mut elem :Asn1Pkcs8PrivKeyInfoElem = Asn1Pkcs8PrivKeyInfoElem::init_asn1();
	let mut algelem :Asn1X509AlgorElem = Asn1X509AlgorElem::init_asn1();
	let mut anydata :Asn1Any = Asn1Any::init_asn1();
	algelem.algorithm.set_value(SM2_OID)?;
	let bdata = algelem.algorithm.encode_asn1()?;
	let _ = anydata.decode_asn1(&bdata)?;	
	algelem.parameters.val = Some(anydata.clone());

	elem.version.val = 0;
	elem.pkeyalg.elem.val.push(algelem);
	elem.pkey.data = incode.to_vec().clone();
	elem.attributes.val = None;
	pk8info.elem.val.push(elem);
	return pk8info.encode_asn1();
}
