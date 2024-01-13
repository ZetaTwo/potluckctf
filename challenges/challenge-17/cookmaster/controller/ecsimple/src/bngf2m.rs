use num_bigint::{BigInt,Sign};

use crate::*;
use crate::consts::*;
use crate::randop::*;
#[allow(unused_imports)]
use crate::logger::*;
use std::ops::{Add,Sub,Mul,Div,Rem,Shl,Shr};
use std::error::Error;

type BValue = u64;

const BVALUE_SIZE :usize = std::mem::size_of::<BValue>();
const BVALUE_BITS :usize = BVALUE_SIZE * 8;

#[derive(Clone)]
pub struct BnGf2m  {
	/*little endian*/
	data :Vec<BValue>,
	polyarr :Vec<i32>,
}

ecsimple_error_class!{BnGf2mError}

impl std::default::Default for BnGf2m {
	fn default() -> Self {
		BnGf2m {
			data :vec![0],
			polyarr : Vec::new(),
		}
	}
}

impl BnGf2m {

	fn _check_self(&self) {
		if self.data.len() == 0 {
			panic!("self len 0");
		}
	}
	fn _check_other(&self,other :&BnGf2m) {
		self._check_self();
		other._check_self();
	}

	pub fn one() -> BnGf2m {
		let v :Vec<u8> = vec![1];
		return BnGf2m::new_from_be(&v);
	}

	pub fn zero() -> BnGf2m {
		let v :Vec<u8> = vec![0];
		return BnGf2m::new_from_be(&v);
	}

	pub fn new_from_le(varr :&[u8]) -> BnGf2m {
		let mut rdata :Vec<BValue> = Vec::new();
		let mut passlen :usize = 0;
		let mut curval :BValue;
		let leftlen :usize;
		while (passlen + BVALUE_SIZE) <= varr.len() {
			curval = 0;
			for i in 0..BVALUE_SIZE {
				curval |= (varr[passlen + i] as BValue) << (i * 8);
			}
			rdata.push(curval);
			passlen += BVALUE_SIZE;
		}

		if passlen != varr.len() {
			curval = 0;
			leftlen = varr.len() - passlen;
			for i in 0..leftlen {
				curval |= (varr[passlen+i] as BValue) << (i * 8);
			}
			rdata.push(curval);
		}
		if rdata.len() == 0 {
			rdata.push(0);
		}

		//ecsimple_debug_buffer_trace!(rdata.as_ptr(), rdata.len() * BVALUE_SIZE, "to bytes");
		let mut retv = BnGf2m {
			data : rdata,
			polyarr : Vec::new(),
		};
		retv._fixup_length();
		retv.extend_poly();
		retv
	}

	pub fn is_zero(&self) -> bool {
		let mut retv : bool =false;
		let (bmax, _) = self._get_max_bits(&self.data);
		if bmax < 0 {
			retv = true;
		}
		return retv;

	}

	pub fn new_from_bigint(bn :&BigInt) -> BnGf2m {
		let varr :Vec<u8>;
		(_, varr) = bn.to_bytes_be();
		return BnGf2m::new_from_be(&varr);
	}

	pub fn new_from_be(varr :&[u8]) -> BnGf2m {
		let mut rdata :Vec<BValue> = Vec::new();
		let mut passlen :usize = 0;
		let leftlen :usize;
		let mut curval :BValue;
		if (varr.len() % BVALUE_SIZE) != 0 {
			leftlen = varr.len() % BVALUE_SIZE;
			curval = 0;
			for i in 0..leftlen {
				curval |= (varr[i] as BValue) << ((leftlen - i - 1) * 8);
			}
			rdata.insert(0,curval);
			passlen += leftlen;
		}
		//ecsimple_debug_buffer_trace!(varr.as_ptr(),varr.len(), "varr ");

		while passlen < varr.len() {
			curval = 0;
			for i in 0..BVALUE_SIZE {
				curval |= (varr[passlen + i] as BValue) << ((BVALUE_SIZE - i - 1) * 8 );
			}
			rdata.insert(0,curval);
			passlen += BVALUE_SIZE;
		}

		if rdata.len() == 0 {
			rdata.push(0);
		}

		//ecsimple_debug_buffer_trace!(rdata.as_ptr(), rdata.len() * BVALUE_SIZE, "to bytes");
		let mut retv = BnGf2m {
			data : rdata,
			polyarr : Vec::new(),
		};
		retv._fixup_length();
		retv.extend_poly();
		retv

	}

	pub fn to_bigint(&self) -> BigInt {
		let mut rdata :Vec<u8> = Vec::new();
		for i in 0..self.data.len() {
			for j in 0..BVALUE_SIZE {
				let val :u8 = (self.data[i] >> (j * 8)) as u8;
				rdata.push(val);
			}
		}
		//ecsimple_debug_buffer_trace!(rdata.as_ptr(), rdata.len(), "to bytes");
		BigInt::from_bytes_le(Sign::Plus,&rdata)
	}

	pub fn sub_op(&self,other :&BnGf2m) -> BnGf2m {
		return self.add_op(other);
	}

	pub fn add_op(&self, other :&BnGf2m) -> BnGf2m {
		let mut retv :Vec<BValue> = Vec::new();
		let mut maxlen :usize = self.data.len();
		let mut aval :BValue;
		let mut bval :BValue;
		let mut rv :BnGf2m;
		let r8 :Vec<u8> = vec![0];
		self._check_other(other);
		if maxlen < other.data.len() {
			maxlen = other.data.len();
		}

		for i in 0..maxlen {
			if i < self.data.len() {
				aval = self.data[i];
			} else {
				aval = 0;
			}
			if i < other.data.len() {
				bval = other.data[i];
			} else {
				bval = 0;
			}

			aval = aval ^ bval;
			retv.push(aval);
		}

		rv = BnGf2m::new_from_be(&r8);
		rv.data= retv;
		rv
	}

	fn _mul_1x1(&self,x0 :BValue,y0 :BValue) -> Vec<BValue> {
		let  (mut h,mut l,mut s) :(BValue,BValue,BValue);
		let mut tab :Vec<BValue> = Vec::new();
		let top3 :BValue = (x0 >> 61) as BValue;
		let (a1,a2,a4,a8):(BValue,BValue,BValue,BValue);
		let mut retv :Vec<BValue> = Vec::new();
		a1 = x0 & (0x1FFFFFFFFFFFFFFF as BValue);
		a2 = a1 << 1;
		a4 = a2 << 1;
		a8 = a4 << 1;
		for _ in 0..16 {
			tab.push(0);
		}

		tab[0] = 0;
		tab[1] = a1;
		tab[2] = a2;
		tab[3] = a1 ^ a2;
		tab[4] = a4;
		tab[5] = a4 ^ a1;
		tab[6] = a4 ^ a2;
		tab[7] = a4 ^ a2 ^ a1;
		tab[8] = a8;
		tab[9] = a8 ^ a1;
		tab[10] = a8 ^ a2;
		tab[11] = a8 ^ a2 ^ a1;
		tab[12] = a8 ^ a4;
		tab[13] = a8 ^ a4 ^ a1;
		tab[14] = a8 ^ a4 ^ a2;
		tab[15] = a8 ^ a4 ^ a2 ^ a1;

		/*for i in 0..tab.len() {
			ecsimple_log_trace!("tab[{}]=[0x{:x}]",i,tab[i]);
		}*/

		//ecsimple_log_trace!("a 0x{:x} b 0x{:x}",x0,y0);

		s = tab[(y0 & 0xF) as usize];
		l = s;
		//ecsimple_log_trace!("l [0x{:x}]",l);

		s = tab[((y0 >> 4) & 0xF) as usize];
		l ^= (s << 4) as BValue;
		h = (s >> 60) as BValue;
		//ecsimple_log_trace!("[{}]l [0x{:x}] h [0x{:x}]",4,l,h);

		s = tab[((y0 >> 8) & 0xF) as usize];
		l ^= (s << 8) as BValue;
		h ^= (s >> 56) as BValue;
		//ecsimple_log_trace!("[{}]l [0x{:x}] h [0x{:x}]",8,l,h);

		s = tab[((y0 >> 12) & 0xF) as usize];
		l ^= (s << 12) as BValue;
		h ^= (s >> 52) as BValue;
		//ecsimple_log_trace!("[{}]l [0x{:x}] h [0x{:x}]",12,l,h);

		s = tab[((y0 >> 16) & 0xF) as usize];
		l ^= (s << 16) as BValue;
		h ^= (s >> 48) as BValue;
		//ecsimple_log_trace!("[{}]l [0x{:x}] h [0x{:x}]",16,l,h);

		s = tab[((y0 >> 20) & 0xF) as usize];
		l ^= (s << 20) as BValue;
		h ^= (s >> 44) as BValue;
		//ecsimple_log_trace!("[{}]l [0x{:x}] h [0x{:x}]",20,l,h);

		s = tab[((y0 >> 24) & 0xF) as usize];
		l ^= (s << 24) as BValue;
		h ^= (s >> 40) as BValue;
		//ecsimple_log_trace!("[{}]l [0x{:x}] h [0x{:x}]",24,l,h);

		s = tab[((y0 >> 28) & 0xF) as usize];
		l ^= (s << 28) as BValue;
		h ^= (s >> 36) as BValue;
		//ecsimple_log_trace!("[{}]l [0x{:x}] h [0x{:x}]",28,l,h);

		s = tab[((y0 >> 32) & 0xF) as usize];
		l ^= (s << 32) as BValue;
		h ^= (s >> 32) as BValue;
		//ecsimple_log_trace!("[{}]l [0x{:x}] h [0x{:x}]",32,l,h);

		s = tab[((y0 >> 36) & 0xF) as usize];
		l ^= (s << 36) as BValue;
		h ^= (s >> 28) as BValue;
		//ecsimple_log_trace!("[{}]l [0x{:x}] h [0x{:x}]",36,l,h);

		s = tab[((y0 >> 40) & 0xF) as usize];
		l ^= (s << 40) as BValue;
		h ^= (s >> 24) as BValue;
		//ecsimple_log_trace!("[{}]l [0x{:x}] h [0x{:x}]",40,l,h);

		s = tab[((y0 >> 44) & 0xF) as usize];
		l ^= (s << 44) as BValue;
		h ^= (s >> 20) as BValue;
		//ecsimple_log_trace!("[{}]l [0x{:x}] h [0x{:x}]",44,l,h);

		s = tab[((y0 >> 48) & 0xF) as usize];
		l ^= (s << 48) as BValue;
		h ^= (s >> 16) as BValue;
		//ecsimple_log_trace!("[{}]l [0x{:x}] h [0x{:x}]",48,l,h);

		s = tab[((y0 >> 52) & 0xF) as usize];
		l ^= (s << 52) as BValue;
		h ^= (s >> 12) as BValue;
		//ecsimple_log_trace!("[{}]l [0x{:x}] h [0x{:x}]",52,l,h);

		s = tab[((y0 >> 56) & 0xF) as usize];
		l ^= (s << 56) as BValue;
		h ^= (s >> 8) as BValue;
		//ecsimple_log_trace!("[{}]l [0x{:x}] h [0x{:x}]",56,l,h);

		s = tab[((y0 >> 60) & 0xF) as usize];
		l ^= (s << 60) as BValue;
		h ^= (s >> 4) as BValue;
		//ecsimple_log_trace!("[{}]l [0x{:x}] h [0x{:x}]",60,l,h);

		if (top3 & 0x1) != 0 {
			l ^= (y0 << 61) as BValue;
			h ^= (y0 >> 3) as BValue;
		}

		if (top3 & 0x2) != 0 {
			l ^= (y0 << 62) as BValue;
			h ^= (y0 >> 2) as BValue;
		}

		if (top3 & 0x4) != 0 {
			l ^= (y0 << 63) as BValue;
			h ^= (y0 >> 1) as BValue;
		}

		retv.push(l);
		retv.push(h);
		//ecsimple_log_trace!("h 0x{:x} l 0x{:x}", h, l);
		retv
	}

	fn _mul_2x2(&self,x0 :BValue,x1 :BValue, y0 :BValue,y1 :BValue) -> Vec<BValue> {
		let mut retv :Vec<BValue> = Vec::new();
		let mut resv :Vec<BValue>;
		//ecsimple_log_trace!("x0 0x{:x} x1 0x{:x} y0 0x{:x} y1 0x{:x}",x0,x1,y0,y1);
		for _ in 0..4 {
			retv.push(0);
		}
		resv = self._mul_1x1(x1,y1);
		retv[2] = resv[0];
		retv[3] = resv[1];
		//ecsimple_log_trace!("retv[3] 0x{:x} retv[2] 0x{:x}",retv[3],retv[2]);

		resv = self._mul_1x1(x0,y0);
		retv[0] = resv[0];
		retv[1] = resv[1];
		//ecsimple_log_trace!("retv[1] 0x{:x} retv[0] 0x{:x}",retv[1],retv[0]);
		resv = self._mul_1x1(x0 ^ x1 , y0 ^ y1);
		//ecsimple_log_trace!("m1 0x{:x} m0 0x{:x}",resv[1],resv[0]);

		retv[2] ^= resv[1] ^ retv[1] ^ retv[3];
		retv[1] = retv[3] ^ retv[2] ^ retv[0] ^ resv[1] ^ resv[0];


		//ecsimple_log_trace!("retv 0x{:x} 0x{:x} 0x{:x} 0x{:x}",retv[3],retv[2],retv[1],retv[0]);
		retv
	}


	pub fn mul_op(&self, other :&BnGf2m) -> BnGf2m {
		let maxlen :usize;
		let alen :usize = self.data.len();
		let olen :usize = other.data.len();
		let r8 :Vec<u8> = vec![0];
		let mut rv :BnGf2m = BnGf2m::new_from_be(&r8);
		let mut retv :Vec<BValue> = Vec::new();
		let (mut y0,mut y1) :(BValue,BValue);
		let (mut x0,mut x1) :(BValue,BValue);
		let (mut i, mut j) : (usize,usize);
		self._check_other(other);

		maxlen = alen + olen + 4;
		for _ in 0..maxlen {
			retv.push(0);
		}

		i = 0;
		while i < alen {
			y0 = self.data[i];
			y1 = 0;
			if (i + 1) < alen {
				y1 = self.data[i+1];
			}
			j = 0;
			while j < olen {
				x0 = other.data[j];
				x1 = 0;
				if (j + 1) < olen {
					x1 = other.data[j+1];
				}

				let resv = self._mul_2x2(x0,x1,y0,y1);
				//ecsimple_log_trace!("resv 0x{:x} 0x{:x} 0x{:x} 0x{:x}",resv[0],resv[1],resv[2],resv[3]);

				for k in 0..resv.len() {
					//ecsimple_log_trace!("[{i}+{j}+{k}] 0x{:x} ^ [{k}] 0x{:x} => 0x{:x}",retv[i+j+k], resv[k],retv[i+j+k] ^ resv[k]);
					retv[i+j+k] ^= resv[k];
					
				}
				j += 2;
			}
			i += 2;
		}
		rv.data = retv;
		rv
	}

	fn _check_mod_val(&self) {
		if self.polyarr.len() == 0 || self.polyarr[self.polyarr.len() - 1] != 0 {
			panic!("0x{:x} not odd for mod", self);
		}
		return;
	}

	fn _extend_poly(&mut self) {
		self.polyarr = Vec::new();
		let mut jdx :i32 ;
		let mut idx :i32;
		//ecsimple_debug_buffer_trace!(self.data.as_ptr(),self.data.len() * std::mem::size_of::<BValue>(),"data set");
		jdx = (self.data.len() - 1)  as i32;
		while jdx >= 0 {
			idx = (BVALUE_BITS - 1) as i32;
			while idx >= 0 {
				if ((self.data[jdx as usize] >> idx) & 0x1) != 0 {
					//ecsimple_log_trace!("push 0x{:x}",jdx * (BVALUE_BITS as i32) + idx);
					self.polyarr.push(jdx * (BVALUE_BITS as i32) + idx);
				}
				idx -= 1;
			}
			jdx -= 1;
		}
		return
	}

	fn _fixup_length(&mut self) {
		let rdata :Vec<BValue> = self.data.clone();
		let mut idx :usize;

		idx = rdata.len() - 1;
		loop {
			if rdata[idx] != 0 || idx == 0 {
				break;
			}
			idx -= 1;
		}

		if idx != (rdata.len() - 1) {
			if idx > 0 {
				self.data = rdata[0..(idx+1)].to_vec();	
			} else {
				self.data = Vec::new();
				self.data.push(rdata[0]);
			}			
		}
		return;
	}

	pub fn extend_poly(&mut self) {
		if self.polyarr.len() > 0 {
			return;
		}
		return self._extend_poly();
	}

	pub fn mod_op(&self,other :&BnGf2m) -> BnGf2m {
		let mut retv :BnGf2m = self.clone();
		let modptr :&BnGf2m;
		modptr = other;
		modptr._check_mod_val();

		//ecsimple_debug_buffer_trace!(modptr.polyarr.as_ptr(), modptr.polyarr.len() * std::mem::size_of::<i32>(),"polyarr {}",modptr.polyarr.len());

		let dn :usize = ((modptr.polyarr[0] as usize) / BVALUE_BITS ) as usize;
		let mut jdx :usize = retv.data.len() - 1;
		let mut n :i32;
		let mut d0 :i32;
		let mut d1 :i32;
		let mut zz :BValue;
		let mut kidx :usize;
		while jdx > dn {
			zz = retv.data[jdx];
			if zz == 0 {
				//ecsimple_log_trace!("[{jdx}] 0");
				jdx -= 1;
				continue;
			}
			retv.data[jdx] = 0;
			kidx = 1;
			while kidx < modptr.polyarr.len() && modptr.polyarr[kidx] != 0 {
				n = modptr.polyarr[0] - modptr.polyarr[kidx];
				//ecsimple_log_trace!("p[0] {} - p[{kidx}] {} = {}", modptr.polyarr[0],modptr.polyarr[kidx],n);
				d0 = n % (BVALUE_BITS as i32);
				d1 = (BVALUE_BITS as i32) - d0;				
				n = n / (BVALUE_BITS as i32);
				//ecsimple_log_trace!("z[{}] (0x{:x}) ^ (0x{:x} >> {}) = 0x{:x}", jdx-(n as usize),retv.data[jdx-(n as usize)],zz,d0,retv.data[jdx-(n as usize)] ^ (zz >> d0));
				retv.data[jdx - (n as usize)] ^= ( zz >> d0) as BValue;
				if d0 != 0 {
					//ecsimple_log_trace!("z[{}] (0x{:x}) ^ (0x{:x} << {}) = 0x{:x}", jdx-(n as usize)-1,retv.data[jdx-(n as usize)-1],zz,d1,retv.data[jdx-(n as usize) - 1] ^ (zz << d1));
					retv.data[jdx - (n as usize) - 1] ^=  zz << d1;
				}
				kidx += 1;
				if kidx < modptr.polyarr.len() {
					//ecsimple_log_trace!("p[{}+1] = {}",kidx-1,modptr.polyarr[kidx]);
				}
			}

			n = dn as i32;
			d0 = modptr.polyarr[0] % (BVALUE_BITS as i32);
			d1 = (BVALUE_BITS as i32) - d0 ;
			//ecsimple_log_trace!("z[{}] (0x{:x}) ^ (0x{:x} >> {}) = 0x{:x}", jdx-(n as usize),retv.data[jdx-(n as usize)],zz,d0,retv.data[jdx-(n as usize)] ^ (zz >> d0));
			retv.data[jdx - (n as usize) ] ^= zz >> d0;
			if d0 != 0 {
				//ecsimple_log_trace!("z[{}] (0x{:x}) ^ (0x{:x} << {}) = 0x{:x}", jdx-(n as usize)-1,retv.data[jdx-(n as usize)-1],zz,d1,retv.data[jdx-(n as usize) - 1] ^ (zz << d1));
				retv.data[jdx - (n  as usize) - 1]  ^= zz << d1;
			} 
		}

		while jdx == dn {
			d0 = modptr.polyarr[0] % (BVALUE_BITS  as i32);
			zz = retv.data[dn] >> d0;
			//ecsimple_log_trace!("z[{}] 0x{:x} >> d0 {} = zz 0x{:x}",dn, retv.data[dn],d0,zz);
			if zz == 0 {
				//ecsimple_log_trace!(" ");
				break;
			}
			d1 = (BVALUE_BITS  as i32) - d0;

			if d0 != 0 {
				//ecsimple_log_trace!("z[{}] (0x{:x} << {}) >> {} = 0x{:x}", dn, retv.data[dn] ,d1,d1, (retv.data[dn] << d1) >> d1);
				retv.data[dn] = (retv.data[dn] << d1) >> d1;
			} else {
				//ecsimple_log_trace!("z[{}] = 0", dn);
				retv.data[dn] = 0;
			}
			//ecsimple_log_trace!("z[0] 0x{:x} ^ 0x{:x} = 0x{:x}", retv.data[0],zz,retv.data[0] ^ zz);
			retv.data[0] ^= zz;

			kidx = 1;
			while kidx < modptr.polyarr.len() && modptr.polyarr[kidx] != 0 {
				let tmp_ulong :BValue;

				n = modptr.polyarr[kidx] / (BVALUE_BITS as i32);
				d0 = modptr.polyarr[kidx] % (BVALUE_BITS  as i32);
				d1 = (BVALUE_BITS as i32)- d0;
				//ecsimple_log_trace!("p[{}] 0x{:x} n {} d0 {} d1 {}",kidx,modptr.polyarr[kidx],n,d0,d1);
				//ecsimple_log_trace!("z[{}] 0x{:x} ^ (zz 0x{:x} << d0 {}) = 0x{:x}", n,retv.data[(n as usize)],zz,d0,retv.data[(n as usize)] ^ (zz << d0));
				retv.data[n as usize] ^= zz << d0;
				tmp_ulong = zz >> d1;
				if d0 != 0 && tmp_ulong != 0 {
					//ecsimple_log_trace!("z[{}] 0x{:x} ^ tmp_ulong 0x{:x} = 0x{:x}", n+1,retv.data[(n as usize)+1],tmp_ulong,retv.data[(n as usize)+1]^tmp_ulong);
					retv.data[(n as usize)+1] ^= tmp_ulong;
				}
				kidx += 1;
			}
		}
		retv._fixup_length();
		retv._extend_poly();
		retv
	}

	fn _get_max_bits(&self,bv :&[BValue]) -> (i32,i32) {
		let mut findidx :i32 = -1;
		let mut bitidx :i32 = -1;
		let mut idx : usize = bv.len() - 1;
		loop  {
			if bv[idx] != 0 {
				findidx = idx as i32;
				break;
			}
			if idx == 0 {
				break;				
			}
			idx -= 1;
		}

		if findidx < 0 {
			/*we just get the value*/
			return (-1,-1);
		}
		idx = BVALUE_BITS - 1;

		loop {
			if ((bv[findidx as usize]) & (1 << idx)) != 0 {
				bitidx = idx as i32;
				break;
			}

			if idx == 0 {
				break;
			}
			idx -= 1;
		}

		return (findidx,bitidx);
	}

	fn _poly_to_bngf2m(&self,poly :&[i32]) -> BnGf2m {
		if poly.len() == 0 {
			let r8 :Vec<u8> = vec![0];
			return BnGf2m::new_from_be(&r8);
		}
		let mut rdata :Vec<BValue> = Vec::new();
		let maxbytes : usize = ((poly[0]  as usize)/ BVALUE_BITS ) + 1;
		for _ in 0..maxbytes {
			rdata.push(0);
		}

		for k in 0..poly.len() {
			let bs = (poly[k] as usize) / BVALUE_BITS  ;
			let bb = (poly[k] as usize)% BVALUE_BITS;
			rdata[bs] |= 1 << bb;
		}

		BnGf2m {
			data : rdata.clone(),
			polyarr : poly.to_vec(),
		}
	}

	pub fn left_shift(&self,shnum :i32) -> BnGf2m {
		let mut retvdata :Vec<BValue> = Vec::new();
		let (mbs,_) = self._get_max_bits(&self.data);
		//ecsimple_log_trace!("0x{:x} mbs {} mbits {}",self,mbs,mbits);
		let r8 :Vec<u8> = vec![0];
		let mut retv :BnGf2m = BnGf2m::new_from_be(&r8);
		if mbs < 0 {
			return retv;
		}
		let maxbytes :i32 = shnum / (BVALUE_BITS as i32) + mbs + 2;
		let addi :i32 = shnum / (BVALUE_BITS as i32);
		let addb :i32 = shnum % (BVALUE_BITS as i32);
		for _ in 0..maxbytes {
			retvdata.push(0);
		}
		let mut i :usize = self.data.len() - 1;
		//ecsimple_log_trace!("retvdata len {}" ,retvdata.len());

		loop {
			if addb > 0 {
				retvdata[i + addi as usize + 1] |= self.data[i] >> (BVALUE_BITS -  addb as usize);
				retvdata[i + addi as usize ] |= self.data[i] << addb;
			} else {
				retvdata[i + addi as usize] |= self.data[i];
			}
			if i == 0 {
				break;
			}
			i -= 1;
		}

		retv.data = retvdata;
		retv._fixup_length();
		retv._extend_poly();
		return retv; 
	}

	pub fn right_shift(&self,shnum :i32) -> BnGf2m {
		let mut retvdata :Vec<BValue> = Vec::new();
		let (mbs,_) = self._get_max_bits(&self.data);
		let r8 :Vec<u8> = vec![0];
		let mut retv :BnGf2m = BnGf2m::new_from_be(&r8);
		if mbs < 0  {
			return retv;
		}
		let addi :i32 = shnum / (BVALUE_BITS as i32);
		let addb :i32 = shnum % (BVALUE_BITS as i32);
		let maxbytes :i32 = mbs + 2;
		for _ in 0..maxbytes {
			retvdata.push(0);
		}
		//ecsimple_log_trace!("addi {} addb {}", addi, addb);

		let mut kidx :usize = self.data.len() - 1;
		/*we just make sure from the most significant bits*/
		while self.data[kidx] == 0  && kidx > 0{
			kidx -= 1;
		}
		while kidx >= addi as usize {
			if addb > 0  {
				if kidx > addi as usize {
					//ecsimple_log_trace!("kidx {} [{}]", kidx,kidx - addi as usize);
					retvdata[kidx - addi as usize] |= self.data[kidx] >> addb;
					retvdata[kidx - addi as usize - 1] |= self.data[kidx] << ( BVALUE_BITS - addb as usize);
				} else {
					retvdata[0] |= self.data[kidx] >> addb;
				}
			} else {
				retvdata[kidx- addi as usize] |= self.data[kidx];
			}
			if kidx == 0 {
				break;
			}
			kidx -= 1;
		}

		retv.data = retvdata;
		retv._fixup_length();
		retv._extend_poly();
		return retv;
	}

	pub fn div_op(&self,other :&BnGf2m) -> BnGf2m {
		let mut d1 :BnGf2m = self.clone();
		let d2 :BnGf2m = other.clone();
		let mut polyarr :Vec<i32> = Vec::new();

		loop {
			let (d1b,d1t) = d1._get_max_bits(&d1.data);
			let (d2b,d2t) = d2._get_max_bits(&d2.data);
			let m1b = d1b * BVALUE_BITS as i32  + d1t;
			let m2b = d2b * BVALUE_BITS as i32 + d2t;
			if m1b < m2b {
				break;
			}		
			let c = d2.left_shift(m1b - m2b);
			let d = d1.sub_op(&c);
			polyarr.push(m1b-m2b);
			d1 = d;
		}

		return self._poly_to_bngf2m(&polyarr);

	}

	pub fn is_one(&self) -> bool {
		if self.max_bits() == 1 {
			return true;
		}
		return false;
	}

	pub fn is_odd(&self) -> bool {
		let mut retv :bool = false;
		if self.data.len() > 0 && (self.data[0] & 0x1) != 0 {
			retv = true;
		}
		return retv;
	}


	pub fn eq_op(&self, v :&BnGf2m) -> bool {
		let mut retv :bool = true;
		let mut idx :usize =0;
		let mut jdx :usize = 0;

		while idx < self.data.len() || jdx < v.data.len() {
			if idx < self.data.len() && jdx < v.data.len() {
				if self.data[idx] != v.data[jdx] {
					retv = false;
					break;
				}
			} else if idx < self.data.len() {
				if self.data[idx] != 0 {
					retv = false;
					break;
				}
			} else if jdx < v.data.len() {
				if v.data[jdx] != 0 {
					retv = false;
					break;
				}
			}
			idx += 1;
			jdx += 1;
		}

		return retv;
	}

	pub fn max_bits(&self) -> i32 {
		if self.polyarr.len() == 0 {
			return 0;
		}
		return (self.polyarr[0] + 1) as i32;
	}

	pub fn inv_op(&self, p :&BnGf2m) -> Result<BnGf2m,Box<dyn Error>> {
		let mut u :BnGf2m = self % p;
		let mut c :BnGf2m = BnGf2m::zero();
		let mut v :BnGf2m = p.clone();
		let mut tmp :BnGf2m;
		let ov :BnGf2m = BnGf2m::one();
		let mut b :BnGf2m = ov.clone();
		if u.is_zero() {
			ecsimple_new_error!{BnGf2mError,"0x{:X} / 0x{:X} == 0", self,p}
		}
		//ecsimple_log_trace!("a 0x{:X} u 0x{:X} p 0x{:X}",self,u,p);

		loop {
			//ecsimple_log_trace!("b 0x{:X} c 0x{:X}",b,c);
			while !u.is_odd() {
				//ecsimple_log_trace!("u 0x{:X}",u);
				if u.is_zero() {
					ecsimple_new_error!{BnGf2mError,"u is zero"}
				}
				u = u >> 1;
				//ecsimple_log_trace!("u 0x{:X} b 0x{:X}", u,b);

				if b.is_odd() {
					b = &b + p;
					//ecsimple_log_trace!("b 0x{:X}", b);
				}

				b = b >> 1;
				//ecsimple_log_trace!("b 0x{:X}",b);
			}

			if u.eq_op(&ov) {
				//ecsimple_log_trace!("u 0x{:X}",u);
				break;
			}

			//ecsimple_log_trace!("u 0x{:X} v 0x{:X}",u,v);
			if u.max_bits() < v.max_bits() {
				//ecsimple_log_trace!("bits u [0x{:x}] bits v [0x{:x}]", u.max_bits(), v.max_bits());
				tmp = u;
				u = v;
				v = tmp;
				tmp = b;
				b = c;
				c = tmp;
				//ecsimple_log_trace!("u <=> v");
			}

			u = &u + &v;
			b = &b + &c;

			//ecsimple_log_trace!("u 0x{:X} b 0x{:X}", u,b);
		}

		return Ok(b);
	}

	///  to find retv ^ 2 + retv = self % pnum values
	/// 
	/// 
	pub fn sqrt_quad_op(&self,pnum :&BnGf2m) -> Result<BnGf2m,Box<dyn Error>> {
		if pnum.polyarr.len() == 0 {
			ecsimple_new_error!{BnGf2mError,"pnum zero"}
		}

		let a :BnGf2m = self.mod_op(pnum);
		let r :BnGf2m;
		let mut jdx :i32;
		let mut z :BnGf2m = BnGf2m::zero();
		let mut w :BnGf2m = BnGf2m::zero();
		let mut w2 :BnGf2m;
		let mut tmp :BnGf2m;

		if a.is_zero() {
			r = BnGf2m::zero();
			return Ok(r);
		}

		if (pnum.polyarr[0] & 0x1) != 0 {
			z = a.clone();
			jdx = 1;
			while jdx <= ((pnum.polyarr[0]-1) >> 1) {
				z = &(&z * &z) % &pnum;
				//ecsimple_log_trace!("[{}] z 0x{:X}",jdx,z);
				z = &(&z * &z) % &pnum;
				//ecsimple_log_trace!("[{}] z 0x{:X}",jdx,z);
				z = z.add_op(&a);
				//ecsimple_log_trace!("[{}] z 0x{:X} a 0x{:X}",jdx,z,a);
				jdx += 1;
			}
		} else {
			let mut count :i32 = 0;
			while count < MAX_ITERATIONS {
				let rhob :BigInt = ecsimple_rand_bits(pnum.polyarr[0] as u64,-1,0);
				let mut rho :BnGf2m = BnGf2m::new_from_bigint(&rhob);
				rho = rho.mod_op(&pnum);
				//ecsimple_log_trace!("rho 0x{:X}",rho);
				z = BnGf2m::zero();
				w = rho.clone();
				jdx = 1;
				while jdx <= (pnum.polyarr[0] - 1) {
					z = &(&z * &z) % &pnum;
					//ecsimple_log_trace!("[{}] z 0x{:X}",jdx,z);
					w2 = &(&w * &w) % &pnum;
					//ecsimple_log_trace!("[{}] w2 0x{:X} w 0x{:X}",jdx,w2,w);
					tmp = &(&w2 * &a) % &pnum;
					//ecsimple_log_trace!("[{}] tmp 0x{:X} = ( w2 0x{:X} * a 0x{:X} )",jdx,tmp,w2,a);
					z = z.add_op(&tmp);
					//ecsimple_log_trace!("[{}] z 0x{:X}",jdx,z);
					w = w2.add_op(&rho);
					//ecsimple_log_trace!("[{}] w 0x{:X} w2 0x{:X} rho 0x{:X}",jdx,w,w2,rho);
					jdx += 1;
				}

				if !w.is_zero() {
					break;
				}
				count += 1;
			}

			if w.is_zero() {
				ecsimple_new_error!{BnGf2mError,"can not resolv 0x{:X} pnum 0x{:X}",self,pnum}
			}
		}

		w = &(&z * &z) % &pnum;
		//ecsimple_log_trace!("w 0x{:X} z 0x{:X}",w,z);
		w = w.add_op(&z);
		//ecsimple_log_trace!("w 0x{:X} z 0x{:X} a 0x{:X}",w,z,a);
		if !w.eq_op(&a) {
			ecsimple_new_error!{BnGf2mError,"can not resolv 0x{:X} pnum 0x{:X}",self,pnum}
		}
		r = z.clone();
		return Ok(r);
	}

}

impl core::fmt::Debug for BnGf2m {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		let bnum :BigInt = self.to_bigint();
		core::fmt::Display::fmt(&bnum, f)
	}
}

impl core::fmt::Display for BnGf2m {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		let bnum :BigInt = self.to_bigint();
		core::fmt::Display::fmt(&bnum,f)
	}
}

impl core::fmt::Binary for BnGf2m {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		let bnum :BigInt = self.to_bigint();
		core::fmt::Binary::fmt(&bnum,f)		
	}
}

impl core::fmt::Octal for BnGf2m {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		let bnum :BigInt = self.to_bigint();
		core::fmt::Octal::fmt(&bnum,f)		
	}
}

impl core::fmt::LowerHex for BnGf2m {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		let bnum :BigInt = self.to_bigint();
		core::fmt::LowerHex::fmt(&bnum,f)
	}
}

impl core::fmt::UpperHex for BnGf2m {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		let bnum :BigInt = self.to_bigint();
		core::fmt::UpperHex::fmt(&bnum,f)		
	}
}


impl Add for BnGf2m {
	type Output = BnGf2m;
	fn add (self,rhs :BnGf2m) -> Self::Output {
		return( &self).add_op(&rhs);
	}
}

impl Add for &BnGf2m {
	type Output = BnGf2m;
	fn add(self, rhs :&BnGf2m) -> Self::Output {
		return self.add_op(rhs);
	}
}

impl Sub for BnGf2m {
	type Output = BnGf2m;
	fn sub (self, rhs :BnGf2m) -> Self::Output {
		return (&self).sub_op(&rhs);
	}
}

impl Sub for &BnGf2m {
	type Output = BnGf2m;
	fn sub (self, rhs :&BnGf2m) -> Self::Output {
		return (self).sub_op(rhs);
	}
}


impl Mul for BnGf2m {
	type Output = BnGf2m;
	fn mul(self, rhs :Self) -> Self::Output {
		return (&self).mul_op(&rhs);
	}
}

impl Mul for &BnGf2m {
	type Output = BnGf2m;
	fn mul(self, rhs :&BnGf2m) -> Self::Output {
		return (self).mul_op(rhs);
	}
}


impl Div for BnGf2m {
	type Output = BnGf2m;
	fn div(self, rhs :Self) -> Self::Output {
		return (&self).div_op(&rhs);
	}
}

impl Div for &BnGf2m {
	type Output = BnGf2m;
	fn div(self, rhs :&BnGf2m) -> Self::Output {
		return (self).div_op(rhs);
	}
}

impl Rem for BnGf2m {
	type Output = BnGf2m;
	fn rem(self, rhs :Self) -> Self::Output {
		return (&self).mod_op(&rhs);
	}
}

impl Rem for &BnGf2m {
	type Output = BnGf2m;
	fn rem(self, rhs :&BnGf2m) -> Self::Output {
		return (self).mod_op(rhs);
	}
}


impl Shl<i32> for BnGf2m {
	type Output = BnGf2m;
	fn shl(self, rhs :i32) -> Self::Output {
		return (&self).left_shift(rhs);
	}
}

impl Shl<i32> for &BnGf2m {
	type Output = BnGf2m;
	fn shl(self, rhs :i32) -> Self::Output {
		return (self).left_shift(rhs);
	}
}

impl Shr<i32> for BnGf2m {
	type Output = BnGf2m;
	fn shr(self, rhs :i32) -> Self::Output {
		return (&self).right_shift(rhs);
	}
}

impl Shr<i32> for &BnGf2m {
	type Output = BnGf2m;
	fn shr(self, rhs :i32) -> Self::Output {
		return (self).right_shift(rhs);
	}
}

