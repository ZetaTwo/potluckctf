
use crate::bngf2m::*;
use crate::group::*;
use crate::utils::*;
use crate::mont::*;
//use crate::consts::*;
use num_bigint::{BigInt};
use num_traits::{zero,one};
use std::error::Error;
use std::cmp::PartialEq;

#[allow(unused_imports)]
use crate::logger::*;
#[allow(unused_imports)]
use crate::randop::*;


ecsimple_error_class!{BnGf2mPointError}

#[derive(Clone)]
pub (crate) struct ECGf2mPoint {
	x :BnGf2m,
	y :BnGf2m,
	z :BnGf2m,
	pub (crate) group :ECGroupBnGf2m,
	infinity : bool,
}

impl std::fmt::Display for ECGf2mPoint {
	fn fmt(&self, f:&mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f,"curve[{}] isinfinity {} x 0x{:x} y 0x{:x} z 0x{:x}", self.group,self.infinity,self.x,self.y,self.z)
	}
}

impl std::default::Default for ECGf2mPoint {
	fn default() -> Self {
		ECGf2mPoint {
			x : BnGf2m::default(),
			y :BnGf2m::default(),
			z :BnGf2m::default(),
			group : ECGroupBnGf2m::default(),
			infinity : true,
		}
	}
}


impl ECGf2mPoint {
	pub fn is_infinity(&self) -> bool {
		return self.infinity;
	}

	pub fn new(grp :&ECGroupBnGf2m) -> ECGf2mPoint {
		ECGf2mPoint {
			x : grp.generator.x.clone(),
			y : grp.generator.y.clone(),
			z : grp.generator.z.clone(),
			group : grp.clone(),
			infinity : false,
		}
	}


	pub fn new_point(x :&BnGf2m, y :&BnGf2m,z :&BnGf2m, grp :&ECGroupBnGf2m) -> Self {
		Self {
			x :x.clone(),
			y :y.clone(),
			z :z.clone(),
			group :grp.clone(),
			infinity : false,
		}
	}



	pub fn set_x(&mut self, x :&BnGf2m) {
		self.x = x.clone();
	}

	pub fn set_y(&mut self, y :&BnGf2m) {
		self.y = y.clone();
	}

	pub fn set_z(&mut self, z :&BnGf2m) {
		self.z = z.clone();
	}

	pub fn x(&self) -> BnGf2m {
		return self.x.clone();
	}

	pub fn y(&self) -> BnGf2m {
		return self.y.clone();
	}

	#[allow(dead_code)]
	pub fn z(&self) -> BnGf2m {
		return self.z.clone();
	}

	pub fn field_mul(&self,a :&BnGf2m, b :&BnGf2m) -> BnGf2m {
		let retv :BnGf2m ;
		retv = a * b;
		let ord :BnGf2m = BnGf2m::new_from_bigint(&self.group.p);
		ecsimple_log_trace!("a 0x{:X} * b 0x{:X} % ord 0x{:X} = 0x{:X}",a,b,ord, retv.clone() % ord.clone());
		return retv % ord;
	}

	pub fn field_sqr(&self,a :&BnGf2m) -> BnGf2m {
		let retv :BnGf2m;
		retv = a * a;
		let ord :BnGf2m = BnGf2m::new_from_bigint(&self.group.p);
		ecsimple_log_trace!("a 0x{:X} * a 0x{:X} % ord 0x{:X} = 0x{:X}",a,a, ord,retv.clone() % ord.clone());
		return retv % ord;		
	}

	pub fn field_div(&self,a :&BnGf2m, b:&BnGf2m) -> Result<BnGf2m,Box<dyn Error>> {
		let fp :BnGf2m = BnGf2m::new_from_bigint(&self.group.p);
		let invb :BnGf2m = b.inv_op(&fp)?;
		ecsimple_log_trace!("0x{:X} * 0x{:X} = 1 % 0x{:X}",invb,b,fp);
		let retv :BnGf2m = invb.mul_op(&a).mod_op(&fp);
		ecsimple_log_trace!("r 0x{:X} = ( y 0x{:X} * xinv 0x{:X} % p 0x{:X} )",retv,a,invb,fp);
		Ok(retv)
	}

	fn ladder_pre(&self, r :&mut ECGf2mPoint, s :&mut ECGf2mPoint, p :&ECGf2mPoint, bits :u64) {
		let mut bs :BigInt;
		bs = ecsimple_rand_bits(bits,-1,0);
		s.z = BnGf2m::new_from_bigint(&bs);
		//ecsimple_log_trace!("random s->Z 0x{:X}", s.z);

		s.x = self.field_mul(&(p.x),&(s.z));
		//ecsimple_log_trace!("s->X 0x{:X}", s.x);


		bs = ecsimple_rand_bits(bits,-1,0);
		r.y = BnGf2m::new_from_bigint(&bs);
		//ecsimple_log_trace!("random r->Y 0x{:X}",r.y);
		r.z = self.field_sqr(&(p.x));
		r.x = self.field_sqr(&(r.z));
		r.x = &r.x + &self.group.b;
		r.z = self.field_mul(&(r.z),&(r.y));
		r.x = self.field_mul(&(r.x),&(r.y));

		ecsimple_log_trace!("r->X 0x{:X} r->Y 0x{:X} r->Z 0x{:X}", r.x,r.y,r.z);

		return;
	}

	fn ladder_step(&self, r :&mut ECGf2mPoint, s :&mut ECGf2mPoint, p :&ECGf2mPoint) {
		r.y = self.field_mul(&(r.z),&(s.x));
		s.x = self.field_mul(&(r.x),&(s.z));
		s.y = self.field_sqr(&(r.z));

		r.z = self.field_sqr(&(r.x));
		s.z = &r.y + &s.x;
		s.z = self.field_sqr(&(s.z));
		s.x = self.field_mul(&(r.y),&(s.x));
		r.y = self.field_mul(&(s.z),&(p.x));
		s.x = &s.x + &r.y;

		r.y = self.field_sqr(&(r.z));
		r.z = self.field_mul(&(r.z),&(s.y));
		s.y = self.field_sqr(&(s.y));
		s.y = self.field_mul(&(s.y),&(self.group.b));
		r.x = &r.y + &s.y;

		return;
	}

	fn make_affine(&self, _r :&mut ECGf2mPoint) {
		return;
	}

	fn point_invert(&self, r :&mut ECGf2mPoint) {
		if r.is_infinity() || r.y.is_zero() {
			return;
		}

		self.make_affine(r);
		r.y = &r.x + &r.y;
		return;
	}

	fn field_inv(&self,a :&BnGf2m) -> BnGf2m {
		let pbn :BnGf2m = BnGf2m::new_from_bigint(&self.group.p);
		let bn = a.inv_op(&pbn).unwrap();
		ecsimple_log_trace!("r 0x{:X} * a 0x{:X} = 1 % 0x{:X}", bn,a,pbn);
		return bn;
	}

	fn ladder_post(&self,r :&mut ECGf2mPoint,s :&ECGf2mPoint,p :&ECGf2mPoint) {
		if r.z.is_zero() {
			r.infinity = true;
			return;
		}
		if s.z.is_zero() {
			*r = p.clone();
			self.point_invert(r);
			return;
		}
		let t0 :BnGf2m;
		let mut t1 :BnGf2m;
		let mut t2 :BnGf2m;

		t0 = self.field_mul(&(r.z),&(s.z));
		t1 = self.field_mul(&(p.x),&(r.z));
		t1 = &r.x + &t1;
		//ecsimple_log_trace!("t1 0x{:X}",t1);
		t2 = self.field_mul(&(p.x),&(s.z));
		r.z = self.field_mul(&(r.x),&t2);
		t2 = &t2 + &s.x;
		//ecsimple_log_trace!("t2 0x{:X}",t2);
		t1 = self.field_mul(&t1,&t2);
		t2 = self.field_sqr(&p.x);
		t2 = &p.y + &t2;
		//ecsimple_log_trace!("t2 0x{:X}",t2);
		t2 = self.field_mul(&t2,&t0);
		t1 = &t2 + &t1;
		//ecsimple_log_trace!("t1 0x{:X}",t1);
		t2 = self.field_mul(&p.x,&t0);
		t2 = self.field_inv(&t2);
		t1 = self.field_mul(&t1,&t2);
		r.x = self.field_mul(&r.z,&t2);
		t2 = &p.x + &r.x;
		//ecsimple_log_trace!("t2 0x{:X}",t2);
		t2 = self.field_mul(&t2,&t1);
		r.y = &p.y + &t2;
		//ecsimple_log_trace!("r->Y 0x{:X}",r.y);
		r.z = BnGf2m::one();
		//ecsimple_log_trace!("r->Z 0x{:X}",r.z);

		return;
	}

	pub fn mulex_op(&self,bn1 :&BigInt,bn2 :&BigInt) -> Result<ECGf2mPoint,Box<dyn Error>> {
		let retv :ECGf2mPoint;
		let t :ECGf2mPoint = self.mul_op(bn1,false);
		let r :ECGf2mPoint = self.mul_op(bn2,true);
		retv = t.add_op_res(&r)?;

		Ok(retv)
	}

	pub fn add_op_res(&self, other :&ECGf2mPoint) -> Result<ECGf2mPoint,Box<dyn Error>> {
		if !self.group.eq_op(&other.group) {
			ecsimple_new_error!{BnGf2mPointError,"self and other not same group"}
		}
		let mut retv :ECGf2mPoint = ECGf2mPoint::default();
		let (x0,y0,x1,y1,mut x2,mut y2) : (BnGf2m,BnGf2m,BnGf2m,BnGf2m,BnGf2m,BnGf2m);
		let (mut s, t) : (BnGf2m,BnGf2m);
		if self.infinity || other.infinity {
			if self.infinity {
				retv = other.clone();
			} else {
				retv = self.clone();
			}			
			return Ok(retv);
		} 
		x0 = self.x.clone();
		y0 = self.y.clone();
		x1 = other.x.clone();
		y1 = other.y.clone();
		ecsimple_log_trace!("x0 0x{:X} y0 0x{:X}",x0,y0);
		ecsimple_log_trace!("x1 0x{:X} y1 0x{:X}",x1,y1);
		if !x0.eq_op(&x1) {
			t = &x0 + &x1;
			ecsimple_log_trace!("t 0x{:X} = x0 0x{:X} + x1 0x{:X}",t,x0,x1);
			s = &y0 + &y1;
			ecsimple_log_trace!("s 0x{:X} = y0 0x{:X} + y1 0x{:X}",s,y0,y1);
			s = self.field_div(&s,&t)?;
			x2 = self.field_sqr(&s);
			x2 = &x2 + &self.group.a;
			ecsimple_log_trace!("x2 0x{:X} group->a 0x{:X}",x2,self.group.a);
			x2 = &x2 + &s;
			ecsimple_log_trace!("x2 0x{:X} s 0x{:X}",x2,s);
			x2 = &x2 + &t;
			ecsimple_log_trace!("x2 0x{:X} t 0x{:X}",x2,t);
		} else {
			if y0.eq_op(&y1) || x1.is_one() {
				retv = ECGf2mPoint::default();
				retv.infinity = true;
				return Ok(retv);
			}
			s = self.field_div(&y1,&x1)?;
			s = &s + &x1;
			ecsimple_log_trace!("s 0x{:X} x1 0x{:X}", s, x1);
			x2 = self.field_sqr(&s);
			x2 = &x2 + &s;
			ecsimple_log_trace!("x2 0x{:X} s 0x{:X}",x2,s);
			x2 = &x2 + &self.group.a;
			ecsimple_log_trace!("x2 0x{:X} group->a 0x{:X}",x2,self.group.a);
		}

		y2 = &x1 + &x2;
		ecsimple_log_trace!("y2 0x{:X} = x1 0x{:X} + x2 0x{:X}",y2,x1,x2);
		y2 = self.field_mul(&y2,&s);
		y2 = &y2 + &x2;
		ecsimple_log_trace!("y2 0x{:X} x2 0x{:X}",y2,x2);
		y2 = &y2 + &y1;
		ecsimple_log_trace!("y2 0x{:X} y1 0x{:X}",y2,y1);

		retv.x = x2.clone();
		retv.y = y2.clone();
		retv.z = BnGf2m::one();
		retv.infinity = false;

		ecsimple_log_trace!("r.x 0x{:X} r.y 0x{:X} r.z 0x{:X}", retv.x,retv.y,retv.z);

		Ok(retv)
	}


	pub fn mul_op(&self, bn :&BigInt,copyxy :bool) -> ECGf2mPoint {
		let zv :BigInt = zero();
		let  p :ECGf2mPoint ;
		let mut s :ECGf2mPoint = ECGf2mPoint::new(&self.group);
		let mut r :ECGf2mPoint = ECGf2mPoint::new(&self.group);
		let mut tmp :ECGf2mPoint;
		let cardinal :BigInt;
		let lamda :BigInt;
		let mut k :BigInt;
		if bn <= &zv {
			r = self.clone();
			r.infinity = true;
			return r;
		}

		if self.infinity {
			return self.clone();
		}

		if copyxy {
			p = self.clone();
		} else {
			p = ECGf2mPoint::new(&self.group);
		}


		if self.group.order == zv || self.group.cofactor == zv {
			panic!("group order 0x{:x} or group cofactor 0x{:x}", self.group.order, self.group.cofactor);
		}

		cardinal = &self.group.order * &self.group.cofactor;

		//ecsimple_log_trace!("field 0x{:X} p 0x{:X}", self.group.p,self.group.p);
		//ecsimple_log_trace!("group->a 0x{:X} a 0x{:X}", self.group.a,self.group.a);
		//ecsimple_log_trace!("group->b 0x{:X} b 0x{:X}", self.group.b,self.group.b);
		//ecsimple_log_trace!("cardinality 0x{:X} order 0x{:X} cofactor 0x{:X}",cardinal,self.group.order,self.group.cofactor);
		//ecsimple_log_trace!("k 0x{:X} lambda 0x{:X}", k, lamda);
		//ecsimple_log_trace!("k 0x{:X} lambda 0x{:X}", k, lamda);

		k = bn.clone();
		lamda = &k + &cardinal;
		ecsimple_log_trace!("scalar 0x{:X} k 0x{:X}",k,k);
		ecsimple_log_trace!("lambda 0x{:X}",lamda);

		k = &lamda + &cardinal;
		//ecsimple_log_trace!("k 0x{:X} cardinality 0x{:X}",k,cardinal);

		let cardbits = get_max_bits(&cardinal);
		let mut i :i32;
		let mut pbit :i32 = 1;
		let mut kbit :i32;
		kbit = get_bit_set(&lamda,cardbits as i32);
		if kbit != 0 {
			//(lamda,k) = (k,lamda);
			k = lamda;
		}
		//ecsimple_log_trace!("k 0x{:X} lambda 0x{:X} cardinality_bits 0x{:x}",k,lamda,cardbits);

		s.x = BnGf2m::zero();
		s.y = BnGf2m::zero();
		s.z = BnGf2m::zero();

		r.x = BnGf2m::zero();
		r.y = BnGf2m::zero();
		r.z = BnGf2m::zero();

		//ecsimple_log_trace!("s.X 0x{:X} s.Y 0x{:X} s.Z 0x{:X}",s.x,s.y,s.z);
		//ecsimple_log_trace!("r.X 0x{:X} r.Y 0x{:X} r.Z 0x{:X}",r.x,r.y,r.z);
		//ecsimple_log_trace!("p.X 0x{:X} p.Y 0x{:X} p.Z 0x{:X}",p.x,p.y,p.z);



		ecsimple_log_trace!("p.X 0x{:X} p.Y 0x{:X} p.Z 0x{:X}",p.x,p.y,p.z);

		self.ladder_pre(&mut r,&mut s, &p, (get_max_bits(&self.group.p) - 1 ) as u64);

		i = (cardbits - 1) as i32;
		while i >= 0 {
			kbit = get_bit_set(&k,i) ^ pbit;
			ecsimple_log_trace!("s.X 0x{:X} s.Y 0x{:X} s.Z 0x{:X}",s.x,s.y,s.z);
			ecsimple_log_trace!("r.X 0x{:X} r.Y 0x{:X} r.Z 0x{:X}",r.x,r.y,r.z);
			ecsimple_log_trace!("[{}]kbit 0x{:x} pbit 0x{:x} [0x{:x}] bitset [0x{:x}]", i,kbit,pbit,i, get_bit_set(&k,i));

			if kbit != 0 {
				tmp = s.clone();
				s = r.clone();
				r = tmp.clone();
			}

			ecsimple_log_trace!("s.X 0x{:X} s.Y 0x{:X} s.Z 0x{:X}",s.x,s.y,s.z);
			ecsimple_log_trace!("r.X 0x{:X} r.Y 0x{:X} r.Z 0x{:X}",r.x,r.y,r.z);

			self.ladder_step(&mut r,&mut s,&p);

			ecsimple_log_trace!("s.X 0x{:X} s.Y 0x{:X} s.Z 0x{:X}",s.x,s.y,s.z);
			ecsimple_log_trace!("r.X 0x{:X} r.Y 0x{:X} r.Z 0x{:X}",r.x,r.y,r.z);
			ecsimple_log_trace!("p.X 0x{:X} p.Y 0x{:X} p.Z 0x{:X}",p.x,p.y,p.z);

			pbit ^= kbit;
			i -= 1;
		}

		ecsimple_log_trace!("s.X 0x{:X} s.Y 0x{:X} s.Z 0x{:X}",s.x,s.y,s.z);
		ecsimple_log_trace!("r.X 0x{:X} r.Y 0x{:X} r.Z 0x{:X}",r.x,r.y,r.z);

		if pbit != 0 {
			tmp = s.clone();
			s = r.clone();
			r = tmp.clone();
		}

		
		ecsimple_log_trace!("s.X 0x{:X} s.Y 0x{:X} s.Z 0x{:X}",s.x,s.y,s.z);
		ecsimple_log_trace!("r.X 0x{:X} r.Y 0x{:X} r.Z 0x{:X}",r.x,r.y,r.z);

		self.ladder_post(&mut r,&mut s,&p);
		//ecsimple_log_trace!("s.X 0x{:X} s.Y 0x{:X} s.Z 0x{:X}",s.x,s.y,s.z);
		ecsimple_log_trace!("r.X 0x{:X} r.Y 0x{:X} r.Z 0x{:X}",r.x,r.y,r.z);
		//ecsimple_log_trace!("p.X 0x{:X} p.Y 0x{:X} p.Z 0x{:X}",p.x,p.y,p.z);

		return r;
	}

	pub fn get_affine_points(&self) -> Result<(BnGf2m,BnGf2m),Box<dyn Error>> {
		if self.infinity {
			ecsimple_new_error!{BnGf2mPointError,"is infinity"}
		}
		if ! self.z.is_one() {
			ecsimple_new_error!{BnGf2mPointError,"z 0x{:X}",self.z}
		}


		Ok((self.x.clone(),self.y.clone()))
	}

	pub fn check_on_curve(&self) -> Result<(),Box<dyn Error>> {
		let mut lh :BnGf2m;
		let y2 :BnGf2m;
		if self.infinity {
			return Ok(());
		}
		if !self.z.is_one() {
			ecsimple_new_error!{BnGf2mPointError,"z 0x{:X} not one",self.z}
		}
		lh = self.x.add_op(&self.group.a);
		lh = self.field_mul(&lh,&self.x);
		lh = lh.add_op(&self.y);
		lh =self.field_mul(&lh,&self.x);
		lh = lh.add_op(&self.group.b);
		y2 = self.field_sqr(&self.y);
		lh = lh.add_op(&y2);
		if !lh.is_zero() {
			ecsimple_new_error!{BnGf2mPointError,"x 0x{:X} y 0x{:X} not on group {}",self.x,self.y,self.group.curvename}
		}
		Ok(())
	}

}


ecsimple_error_class!{ECPrimePointError}

#[derive(Clone)]
pub (crate) struct ECPrimePoint {
	x :BigInt,
	y :BigInt,
	z :BigInt,
	pub (crate) group :ECGroupPrime,
	montv : MontNum,
	infinity : bool,
	z_is_one : bool,
}

impl std::fmt::Display for ECPrimePoint {
	fn fmt(&self, f:&mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f,"curve[{}] isinfinity {} x 0x{:x} y 0x{:x} z 0x{:x}", self.group,self.infinity,self.x,self.y,self.z)
	}
}

impl PartialEq for ECPrimePoint {
	fn eq(&self, other:&Self) -> bool {
		return self.eq_op(other);
	}

	fn ne(&self, other:&Self) -> bool {
		return ! self.eq_op(other);
	}
}


impl std::default::Default for ECPrimePoint {
	fn default() -> Self {
		let ov :BigInt = one();
		let tv :BigInt = ov.clone() + ov.clone() + ov.clone();
		ECPrimePoint {
			x : zero(),
			y : zero(),
			z : zero(),
			group : ECGroupPrime::default(),
			montv : MontNum::new(&tv).unwrap(),
			infinity : true,
			z_is_one : true,
		}
	}
}

impl ECPrimePoint {
	pub (crate) fn new(grp :&ECGroupPrime) -> ECPrimePoint {
		let pnt :ECPrimePoint = ECPrimePoint {
			x : grp.generator.x.clone(),
			y : grp.generator.y.clone(),
			z : grp.generator.z.clone(),
			group : grp.clone(),
			montv : MontNum::new(&grp.p).unwrap(),
			infinity : false,
			z_is_one : true,
		};
		return pnt;
	}

	pub (crate) fn new_point(x :&BigInt, y :&BigInt,z :&BigInt, grp :&ECGroupPrime) -> Self {
		let pnt : ECPrimePoint = Self {
			x :x.clone(),
			y :y.clone(),
			z :z.clone(),
			group :grp.clone(),
			montv : MontNum::new(&grp.p).unwrap(),
			infinity : false,
			z_is_one : true,
		};
		return pnt;
	}


	pub fn set_x(&mut self, x :&BigInt) {
		self.x = x.clone();
	}

	pub fn set_y(&mut self, y :&BigInt) {
		self.y = y.clone();
	}

	pub fn set_z(&mut self, z :&BigInt) {
		self.z = z.clone();
	}


	pub fn x(&self) -> BigInt {
		return self.x.clone();
	}

	pub fn y(&self) -> BigInt {
		return self.y.clone();
	}

	#[allow(dead_code)]
	pub fn z(&self) -> BigInt {
		return self.z.clone();
	}


	pub fn field_sqr(&self,a :&BigInt) -> BigInt {
		let retv :BigInt = self.montv.mont_mul(a,a);
		ecsimple_log_trace!("r 0x{:X} = a 0x{:X} ^ 2 % group.field 0x{:X}",retv,a,self.group.p);
		return retv;
	}

	pub fn field_mul(&self,a :&BigInt,b :&BigInt) -> BigInt {
		let retv :BigInt = self.montv.mont_mul(a,b);
		ecsimple_log_trace!("r 0x{:X} = a 0x{:X} * b 0x{:X} % m 0x{:X}",retv,a,b,self.group.p);
		return retv;
	}

	pub fn sub_mod_quick(&self,a :&BigInt,b :&BigInt,m :&BigInt) -> BigInt {
		let mut r :BigInt;
		let zv :BigInt = zero();
		r = a - b;
		if r < zv {
			r += m;
		}
		return r;
	}

	pub (crate) fn lshift_mod_quick(&self,a :&BigInt,sn :i64, m :&BigInt) -> BigInt {
		let r :BigInt;
		r = a << sn;
		return r % m;
	}

	pub (crate) fn lshift1_mod_quick(&self,a :&BigInt,m :&BigInt) -> BigInt {
		let r :BigInt;
		r = a << 1;
		return r % m;
	}

	pub (crate) fn add_mod_quick(&self,a :&BigInt,b :&BigInt, m :&BigInt) -> BigInt {
		let retv :BigInt;
		retv = a + b;
		return retv % m;
	}

	fn field_encode(&self,a :&BigInt) -> BigInt {
		let retv :BigInt;
		retv = self.montv.mont_to(a);
		ecsimple_log_trace!("r 0x{:X} = BN_to_montgomery(a 0x{:X},field 0x{:X});",retv,a,self.group.p);
		return retv;
	}


	#[allow(unused_variables)]
	fn ladder_pre(&self, r :&mut ECPrimePoint, s :&mut ECPrimePoint, p :&ECPrimePoint, bits :u64) {
		let mut rndv :BigInt;
		let zv :BigInt = zero();
		ecsimple_log_trace!("ladder_pre");
		/*
		* t1 s.z
		* t2 r.z
		* t3 s.x
		* t4 r.x
		* t5 s.y
		*/
		s.x = self.field_sqr(&p.x);
		r.x = self.sub_mod_quick(&s.x,&self.group.a,&self.group.p);
		ecsimple_log_trace!("r.x 0x{:X} = sub_mod_quick(s.x 0x{:X},group.a 0x{:X},group.field 0x{:X})",r.x,s.x,self.group.a,self.group.p);
		r.x = self.field_sqr(&r.x);
		s.y = self.field_mul(&p.x,&self.group.b);
		s.y = self.lshift_mod_quick(&s.y,3,&self.group.p);
		ecsimple_log_trace!("s.y 0x{:X} = s.y << 3 % 0x{:X}",s.y,self.group.p);
		r.x = self.sub_mod_quick(&r.x,&s.y,&self.group.p);
		ecsimple_log_trace!("r.X 0x{:X} = sub_mod_quick(r.x 0x{:X},s.y 0x{:X},group.field 0x{:X})",r.x,r.x,s.y,self.group.p);
		s.z = self.add_mod_quick(&s.x,&self.group.a,&self.group.p);
		ecsimple_log_trace!("s.z 0x{:X} = add_mod_quick(s.x 0x{:X},group.a 0x{:X},group.field 0x{:X})",s.z,s.x,self.group.a,self.group.p);

		r.z = self.field_mul(&p.x,&s.z);
		r.z = self.add_mod_quick(&self.group.b,&r.z,&self.group.p);
		ecsimple_log_trace!("r.z 0x{:X} = add_mod_quick(group.b 0x{:X},r.z,group.field 0x{:X})",r.z,self.group.b,self.group.p);
		r.z = self.lshift_mod_quick(&r.z,2,&self.group.p);
		ecsimple_log_trace!("r.z 0x{:X} = lshift_mod_quick(r.z,2,group.field 0x{:X})", r.z,self.group.p);
		ecsimple_log_trace!("before rnd points");
		loop {
			rndv = ecsimple_private_rand_range(&self.group.p);
			if rndv != zv {
				r.y = rndv.clone();
				break;
			}	
		}
		
		loop {
			rndv = ecsimple_private_rand_range(&self.group.p);
			if rndv != zv {
				s.z = rndv.clone();
				break;
			}
		}
		ecsimple_log_trace!("after rnd points");

		r.y = self.field_encode(&r.y);
		s.z = self.field_encode(&s.z);

		r.z = self.field_mul(&r.z,&r.y);
		r.x = self.field_mul(&r.x,&r.y);

		s.x = self.field_mul(&p.x,&s.z);



		return;
	}

	fn ladder_step(&self, r :&mut ECPrimePoint, s :&mut ECPrimePoint, p :&ECPrimePoint) {
		let mut t0 :BigInt;
		let mut t1 :BigInt;
		let t2 :BigInt;
		let mut t3 :BigInt;
		let mut t4 :BigInt;
		let mut t5 :BigInt;
		let mut t6 :BigInt;

		t6 = self.field_mul(&r.x,&s.x);
		t0 = self.field_mul(&r.z,&s.z);
		t4 = self.field_mul(&r.x,&s.z);
		t3 = self.field_mul(&r.z,&s.x);
		t5 = self.field_mul(&self.group.a,&t0);
		t5 = self.add_mod_quick(&t6,&t5,&self.group.p);
		ecsimple_log_trace!("add_mod_quick(t5 0x{:X},t6 0x{:X},t5,group.field 0x{:X})",t5,t6,self.group.p);
		t6 = self.add_mod_quick(&t3,&t4,&self.group.p);
		ecsimple_log_trace!("add_mod_quick(t6 0x{:X},t3 0x{:X},t4 0x{:X},group.field 0x{:X})",t6,t3,t4,self.group.p);
		t5 = self.field_mul(&t6,&t5);
		t0 = self.field_sqr(&t0);
		t2 = self.lshift_mod_quick(&self.group.b,2,&self.group.p);
		ecsimple_log_trace!("mod_lshift_quick(t2 0x{:X},group.b 0x{:X},2,group.field 0x{:X})",t2,self.group.b,self.group.p);
		t0 = self.field_mul(&t2,&t0);
		t5 = self.lshift1_mod_quick(&t5 , &self.group.p);
		ecsimple_log_trace!("lshift1_mod_quick(t5 0x{:X},t5,group.field 0x{:X})",t5,self.group.p);
		t3 = self.sub_mod_quick(&t4,&t3,&self.group.p);
		ecsimple_log_trace!("sub_mod_quick(t3 0x{:X},t4 0x{:X},t3,group.field 0x{:X})",t3,t4,self.group.p);
		s.z = self.field_sqr(&t3);
		t4 = self.field_mul(&s.z,&p.x);
		t0 = self.add_mod_quick(&t0,&t5,&self.group.p);
		ecsimple_log_trace!("add_mod_quick(t0 0x{:X},t0,t5 0x{:X},group.field 0x{:X})",t0,t5,self.group.p);
		s.x = self.sub_mod_quick(&t0,&t4,&self.group.p);
		ecsimple_log_trace!("sub_mod_quick(s.x 0x{:X},t0 0x{:X},t4 0x{:X},group.field 0x{:X})",s.x,t0,t4,self.group.p);
		t4 = self.field_sqr(&r.x);
		t5 = self.field_sqr(&r.z);
		t6 = self.field_mul(&t5,&self.group.a);
		ecsimple_log_trace!("new t6 0x{:X}",t6);
		t1 = self.add_mod_quick(&r.x,&r.z,&self.group.p);
		ecsimple_log_trace!("add_mod_quick(t1 0x{:X},r.x 0x{:X},r.z 0x{:X},group.field 0x{:X})",t1,r.x,r.z,self.group.p);
		t1 = self.field_sqr(&t1);
		t1 = self.sub_mod_quick(&t1,&t4,&self.group.p);
		ecsimple_log_trace!("sub_mod_quick(t1 0x{:X},t1,t4 0x{:X},group.field 0x{:X})",t1,t4,self.group.p);
		t1 = self.sub_mod_quick(&t1,&t5,&self.group.p);
		ecsimple_log_trace!("sub_mod_quick(t1 0x{:X},t1,t5 0x{:X},group.field 0x{:X})",t1,t5,self.group.p);
		t3 = self.sub_mod_quick(&t4,&t6,&self.group.p);
		ecsimple_log_trace!("sub_mod_quick(t3 0x{:X},t4 0x{:X},t6 0x{:X},group.field 0x{:X})",t3,t4,t6,self.group.p);
		t3 = self.field_sqr(&t3);
		t0 = self.field_mul(&t5,&t1);
		t0 = self.field_mul(&t2,&t0);
		r.x = self.sub_mod_quick(&t3,&t0,&self.group.p);
		ecsimple_log_trace!("sub_mod_quick(r.x 0x{:X},t3 0x{:X},t0 0x{:X},group.field 0x{:X})",r.x,t3,t0,self.group.p);
		t3 = self.add_mod_quick(&t4,&t6,&self.group.p);
		ecsimple_log_trace!("add_mod_quick(t3 0x{:X},t4 0x{:X},t6 0x{:X},group.field 0x{:X})",t3,t4,t6,self.group.p);
		t4 = self.field_sqr(&t5);
		t4 = self.field_mul(&t4,&t2);
		t1 = self.field_mul(&t1,&t3);
		t1 = self.lshift1_mod_quick(&t1,&self.group.p);
		ecsimple_log_trace!("lshift1_mod_quick(t1 0x{:X},t1,group.field 0x{:X})",t1,self.group.p);
		r.z = self.add_mod_quick(&t4,&t1,&self.group.p);
		ecsimple_log_trace!("add_mod_quick(r.z 0x{:X},t4 0x{:X},t1 0x{:X},group.field 0x{:X})",r.z,t4,t1,self.group.p);
		return;
	}

	pub (crate) fn field_decode(&self,a :&BigInt) -> BigInt {
		let retv :BigInt =  self.montv.mont_from(a);
		return retv;
	}

	fn field_inv(&self,a :&BigInt) -> BigInt {
		let ov :BigInt = one();

		let e :BigInt = &self.group.p - &ov - &ov;
		let retv:BigInt =  self.montv.mont_pow(a,&e);
		ecsimple_log_trace!("field_inv(r 0x{:X},a 0x{:X},e 0x{:X},group.field 0x{:X})",retv,a,e,self.group.p);
		return retv;
	}

	fn field_set_to_one(&self) -> BigInt {
		let retv :BigInt = self.group.generator.z.clone();
		ecsimple_log_trace!("set_to_one(r 0x{:X})",retv);
		return retv;
	}

	fn ladder_post(&self, r :&mut ECPrimePoint, s :&mut ECPrimePoint, p :&ECPrimePoint) {
		let mut t0 :BigInt;
		let mut t1 :BigInt;
		let t2 :BigInt;
		let t3 :BigInt;
		let t4 :BigInt;
		let t5 :BigInt;
		let mut t6 :BigInt;

		t4 = self.lshift1_mod_quick(&p.y,&self.group.p);
		ecsimple_log_trace!("lshift1_mod_quick(t4 0x{:X},p.y 0x{:X},group.field 0x{:X})",t4,p.y,self.group.p);
		t6 = self.field_mul(&r.x,&t4);
		t6 = self.field_mul(&s.z,&t6);
		t5 = self.field_mul(&r.z,&t6);

		t1 = self.lshift1_mod_quick(&self.group.b,&self.group.p);
		ecsimple_log_trace!("lshift1_mod_quick(t1 0x{:X},group.b 0x{:X},group.field 0x{:X})",t1,self.group.b,self.group.p);
		t1 = self.field_mul(&s.z,&t1);
		t3 = self.field_sqr(&r.z);
		t2 = self.field_mul(&t3,&t1);
		t6 = self.field_mul(&r.z,&self.group.a);
		t1 = self.field_mul(&p.x,&r.x);
		t1 = self.add_mod_quick(&t1,&t6,&self.group.p);
		ecsimple_log_trace!("add_mod_quick(t1 0x{:X},t1,t6 0x{:X},group.field 0x{:X})",t1,t6,self.group.p);
		t1 = self.field_mul(&s.z,&t1);
		t0 = self.field_mul(&p.x,&r.z);
		t6 = self.add_mod_quick(&r.x,&t0,&self.group.p);
		ecsimple_log_trace!("add_mod_quick(t6 0x{:X},r.x 0x{:X},t0 0x{:X},group.field 0x{:X})",t6,r.x,t0,self.group.p);
		t6 = self.field_mul(&t6,&t1);
		t6 = self.add_mod_quick(&t6,&t2,&self.group.p);
		ecsimple_log_trace!("add_mod_quick(t6 0x{:X},t6,t2 0x{:X},group.field 0x{:X})",t6,t2,self.group.p);
		t0 = self.sub_mod_quick(&t0,&r.x,&self.group.p);
		ecsimple_log_trace!("sub_mod_quick(t0 0x{:X},t0,r.x 0x{:X},group.field 0x{:X})",t0,r.x,self.group.p);
		t0 = self.field_sqr(&t0);
		t0 = self.field_mul(&t0,&s.x);
		t0 = self.sub_mod_quick(&t6,&t0,&self.group.p);
		ecsimple_log_trace!("sub_mod_quick(t0 0x{:X},t6 0x{:X},t0,group.field 0x{:X})",t0,t6,self.group.p);
		t1 = self.field_mul(&s.z,&t4);
		t1 = self.field_mul(&t3,&t1);
		t1 = self.field_decode(&t1);
		t1 = self.field_inv(&t1);
		t1 = self.field_encode(&t1);
		r.x = self.field_mul(&t5,&t1);
		r.y = self.field_mul(&t0,&t1);
		r.z = self.field_set_to_one();

		return;
	}

	pub fn get_affine_coordinates(&self,r :&ECPrimePoint) -> ECPrimePoint  {
		ecsimple_log_trace!("point.X 0x{:X} point.Y 0x{:X} point.Z 0x{:X}",r.x,r.y,r.z);
		let mut retv :ECPrimePoint = r.clone();
		retv.z = self.montv.mont_from(&r.z);
		retv.x = self.montv.mont_from(&r.x);
		retv.y = self.montv.mont_from(&r.y);
		ecsimple_log_trace!("x 0x{:X} y 0x{:X} z 0x{:X}",retv.x,retv.y,retv.z);
		return retv;
	}

	pub fn set_affine_coordinates(&self,x :&BigInt,y :&BigInt,z :&BigInt) -> Result<ECPrimePoint,Box<dyn Error>> {
		let mut retv :ECPrimePoint = ECPrimePoint::new(&self.group);
		ecsimple_log_trace!("field 0x{:X}",self.group.p);
		ecsimple_log_trace!("x 0x{:X} y 0x{:X} z 0x{:X}",x,y,z);
		retv.x = nmod(x,&self.group.p);
		ecsimple_log_trace!("point->X 0x{:X} = x 0x{:X} % group->field 0x{:X}", retv.x,x,self.group.p);
		retv.x = self.field_encode(&retv.x);
		ecsimple_log_trace!("field_encode point->X 0x{:X}",retv.x);

		retv.y = nmod(y,&self.group.p);
		ecsimple_log_trace!("point->Y 0x{:X} = y 0x{:X} % group->field 0x{:X}", retv.y,y,self.group.p);
		retv.y = self.field_encode(&retv.y);
		ecsimple_log_trace!("field_encode point->Y 0x{:X}",retv.y);

		retv.z = nmod(z,&self.group.p);
		ecsimple_log_trace!("point->Z 0x{:X} = z 0x{:X} % group->field 0x{:X}",retv.z,z,self.group.p);
		retv.z = self.field_set_to_one();
		ecsimple_log_trace!("field_set_to_one point->Z 0x{:X}",retv.z);

		Ok(retv)
	}





	#[allow(unused_assignments)]
	#[allow(unused_variables)]
	pub fn mul_op(&self, bn :&BigInt,copyxy :bool ) -> ECPrimePoint {
		let zv :BigInt = zero();
		let  p :ECPrimePoint ;
		let mut s :ECPrimePoint = ECPrimePoint::new(&self.group);
		let mut r :ECPrimePoint = ECPrimePoint::new(&self.group);
		let mut tmp :ECPrimePoint;
		let cardinal :BigInt;
		let mut lamda :BigInt = zero();
		let mut k :BigInt = zero();
		if bn <= &zv {
			r = self.clone();
			r.infinity = true;
			return r;
		}

		if self.infinity {
			return self.clone();
		}

		if copyxy {
			p = self.clone();
		} else {
			p = ECPrimePoint::new(&self.group);
		}
		ecsimple_log_trace!("p.x 0x{:X} p.y 0x{:X} p.z 0x{:X}",p.x,p.y,p.z);


		if self.group.order == zv || self.group.cofactor == zv {
			panic!("group order 0x{:x} or group cofactor 0x{:x}", self.group.order, self.group.cofactor);
		}

		cardinal = &self.group.order * &self.group.cofactor;

		//ecsimple_log_trace!("field 0x{:X} p 0x{:X}", self.group.p,self.group.p);
		//ecsimple_log_trace!("group->a 0x{:X} a 0x{:X}", self.group.a,self.group.a);
		//ecsimple_log_trace!("group->b 0x{:X} b 0x{:X}", self.group.b,self.group.b);
		//ecsimple_log_trace!("cardinality 0x{:X} order 0x{:X} cofactor 0x{:X}",cardinal,self.group.order,self.group.cofactor);
		ecsimple_log_trace!("k 0x{:X} lambda 0x{:X}", k, lamda);
		//ecsimple_log_trace!("k 0x{:X} lambda 0x{:X}", k, lamda);

		k = bn.clone();
		lamda = &k + &cardinal;
		ecsimple_log_trace!("scalar 0x{:X} k 0x{:X}",k,k);
		ecsimple_log_trace!("lambda 0x{:X}",lamda);

		let mut kbit :i32;
		k = &lamda + &cardinal;
		ecsimple_log_trace!("k 0x{:X} cardinality 0x{:X}",k,cardinal);

		let cardbits = get_max_bits(&cardinal);
		kbit = get_bit_set(&lamda,cardbits as i32);
		if kbit != 0 {
			(lamda,k) = (k,lamda);
		}

		let mut i :i32;
		let mut pbit :i32 = 1;
		ecsimple_log_trace!("k 0x{:X} lambda 0x{:X} cardinality_bits 0x{:x}",k,lamda,cardbits);

		s.x = zero();
		s.y = zero();
		s.z = zero();

		r.x = zero();
		r.y = zero();
		r.z = zero();

		//ecsimple_log_trace!("s.X 0x{:X} s.Y 0x{:X} s.Z 0x{:X}",s.x,s.y,s.z);
		//ecsimple_log_trace!("r.X 0x{:X} r.Y 0x{:X} r.Z 0x{:X}",r.x,r.y,r.z);
		//ecsimple_log_trace!("p.X 0x{:X} p.Y 0x{:X} p.Z 0x{:X}",p.x,p.y,p.z);



		ecsimple_log_trace!("p.X 0x{:X} p.Y 0x{:X} p.Z 0x{:X}",p.x,p.y,p.z);


		ecsimple_log_trace!("p.X 0x{:X} p.Y 0x{:X} p.Z 0x{:X}",p.x,p.y,p.z);
		self.ladder_pre(&mut r,&mut s, &p, (get_max_bits(&self.group.p) - 1 ) as u64);

		i = (cardbits - 1) as i32;
		while i >= 0 {
			kbit = get_bit_set(&k,i) ^ pbit;
			ecsimple_log_trace!("s.X 0x{:X} s.Y 0x{:X} s.Z 0x{:X}",s.x,s.y,s.z);
			ecsimple_log_trace!("r.X 0x{:X} r.Y 0x{:X} r.Z 0x{:X}",r.x,r.y,r.z);
			ecsimple_log_trace!("[{}]kbit 0x{:x} pbit 0x{:x} [0x{:x}] bitset [0x{:x}]", i,kbit,pbit,i, get_bit_set(&k,i));

			if kbit != 0 {
				tmp = s.clone();
				s = r.clone();
				r = tmp.clone();
			}

			ecsimple_log_trace!("s.X 0x{:X} s.Y 0x{:X} s.Z 0x{:X}",s.x,s.y,s.z);
			ecsimple_log_trace!("r.X 0x{:X} r.Y 0x{:X} r.Z 0x{:X}",r.x,r.y,r.z);

			self.ladder_step(&mut r,&mut s,&p);

			ecsimple_log_trace!("s.X 0x{:X} s.Y 0x{:X} s.Z 0x{:X}",s.x,s.y,s.z);
			ecsimple_log_trace!("r.X 0x{:X} r.Y 0x{:X} r.Z 0x{:X}",r.x,r.y,r.z);
			ecsimple_log_trace!("p.X 0x{:X} p.Y 0x{:X} p.Z 0x{:X}",p.x,p.y,p.z);

			pbit ^= kbit;
			i -= 1;
		}

		ecsimple_log_trace!("s.X 0x{:X} s.Y 0x{:X} s.Z 0x{:X}",s.x,s.y,s.z);
		ecsimple_log_trace!("r.X 0x{:X} r.Y 0x{:X} r.Z 0x{:X}",r.x,r.y,r.z);

		if pbit != 0 {
			tmp = s.clone();
			s = r.clone();
			r = tmp.clone();
		}

		
		ecsimple_log_trace!("s.X 0x{:X} s.Y 0x{:X} s.Z 0x{:X}",s.x,s.y,s.z);
		ecsimple_log_trace!("r.X 0x{:X} r.Y 0x{:X} r.Z 0x{:X}",r.x,r.y,r.z);

		self.ladder_post(&mut r,&mut s,&p);
		//ecsimple_log_trace!("s.X 0x{:X} s.Y 0x{:X} s.Z 0x{:X}",s.x,s.y,s.z);
		ecsimple_log_trace!("r.X 0x{:X} r.Y 0x{:X} r.Z 0x{:X}",r.x,r.y,r.z);
		//ecsimple_log_trace!("p.X 0x{:X} p.Y 0x{:X} p.Z 0x{:X}",p.x,p.y,p.z);

		r = self.get_affine_coordinates(&r);

		return r;
	}

	pub fn check_on_curve(&self) -> Result<(),Box<dyn Error>> {
		let mut rh :BigInt;
		let ov :BigInt = one();
		let z4 :BigInt;
		let z6 :BigInt;
		let mut tmp :BigInt;
		let field :BigInt = self.group.p.clone();

		rh = self.field_sqr(&self.x);
		if self.z != ov {
			tmp = self.field_sqr(&self.z);
			z4 = self.field_sqr(&tmp);
			z6 = self.field_mul(&z4,&tmp);

			if self.group.is_minus3 {
				tmp = self.lshift1_mod_quick(&z4,&field);
				ecsimple_log_trace!("lshift1_mod_quick(tmp 0x{:X},Z4 0x{:X},p 0x{:X})",tmp,z4,field);
				tmp = self.add_mod_quick(&tmp,&z4,&field);
				ecsimple_log_trace!("add_mod_quick(tmp 0x{:X},tmp,Z4 0x{:X},p 0x{:X})",tmp,z4,field);
				rh = self.sub_mod_quick(&rh,&tmp,&field);
				ecsimple_log_trace!("sub_mod_quick(rh 0x{:X},rh,tmp 0x{:X},p 0x{:X})",rh,tmp,field);
				rh = self.field_mul(&rh,&self.x);
			} else {
				tmp = self.field_mul(&z4,&self.group.a);
				rh = self.add_mod_quick(&rh,&tmp,&field);
				ecsimple_log_trace!("add_mod_quick(rh 0x{:X},rh,tmp 0x{:X},p 0x{:X})",rh,tmp,field);
				rh = self.field_mul(&rh,&self.x);
			}
			tmp = self.field_mul(&self.group.b,&z6);
			rh = self.add_mod_quick(&rh,&tmp,&field);
			ecsimple_log_trace!("add_mod_quick(rh 0x{:X},rh,tmp 0x{:X},p 0x{:X})",rh,tmp,field);
		} else {
			rh = self.add_mod_quick(&rh,&self.group.a,&field);
			ecsimple_log_trace!("add_mod_quick(rh 0x{:X},rh,group.a 0x{:X},p 0x{:X})",rh, self.group.a,field);
			rh = self.field_mul(&rh,&self.x);
			rh = self.add_mod_quick(&rh,&self.group.b,&field);
			ecsimple_log_trace!("add_mod_quick(rh 0x{:X},rh,group.b 0x{:X},p 0x{:X})",rh,self.group.b,field);
		}

		tmp = self.field_sqr(&self.y);
		if tmp != rh {
			ecsimple_new_error!{ECPrimePointError,"tmp 0x{:X} != rh 0x{:X}",tmp,rh}
		}
		Ok(())
	}

	fn get_wnaf_variable(&self,bn :&BigInt) -> Result<(Vec<u8>,i32),Box<dyn Error>> {
		let wnaf_bit :i32 = get_wnaf_bits(bn);
		let curnaf :Vec<u8> = wnaf_value(bn,wnaf_bit)?;
		Ok((curnaf,wnaf_bit))
	}

	fn dbl(&self) -> Result<ECPrimePoint,Box<dyn Error>> {
		let mut retv :ECPrimePoint = ECPrimePoint::new(&self.group);
		let zv :BigInt = zero();
		let field :BigInt = self.group.p.clone();
		let mut n0 :BigInt;
		let mut n1 :BigInt;
		let mut n2 :BigInt;
		let mut n3 :BigInt;

		if self.infinity {
			retv.z = zv.clone();
			retv.z_is_one = false;
			return Ok(retv);
		}

		if self.z_is_one {
			n0 = self.field_sqr(&self.x);
			n1 = self.lshift1_mod_quick(&n0,&field);
			ecsimple_log_trace!("mod_lshift_quick(n1 0x{:X},n0 0x{:X},p 0x{:X})",n1,n0,field);
			n0 = self.add_mod_quick(&n0,&n1,&field);
			ecsimple_log_trace!("mod_add_quick(n0 0x{:X},n0,n1 0x{:X},p 0x{:X})",n0,n1,field);
			n1 = self.add_mod_quick(&n0,&self.group.a,&field);
			ecsimple_log_trace!("mod_add_quick(n1 0x{:X},n0 0x{:X},group.a 0x{:X},p 0x{:X})",n1,n0,self.group.a,field);
			/* n1 = 3 * X_a^2 + a_curve */
		} else if self.group.is_minus3 {
			n1 = self.field_sqr(&self.z);
			n0 = self.add_mod_quick(&self.x,&n1,&field);
			ecsimple_log_trace!("mod_add_quick(n0 0x{:X},a.x 0x{:X},n1 0x{:X},p 0x{:X})",n0,self.x,n1,field);
			n2 = self.sub_mod_quick(&self.x,&n1,&field);
			ecsimple_log_trace!("mod_sub_quick(n2 0x{:X},a.x 0x{:X},n1 0x{:X},p 0x{:X})",n2,self.x,n1,field);
			n1 = self.field_mul(&n0,&n2);
			n0 = self.lshift1_mod_quick(&n1,&field);
			ecsimple_log_trace!("mod_lshift_quick(n0 0x{:X},n1 0x{:X},p 0x{:X})",n0, n1,field);
			n1 = self.add_mod_quick(&n0,&n1,&field);
			ecsimple_log_trace!("mod_add_quick(n1 0x{:X},n0 0x{:X},n1,p 0x{:X})",n1,n0,field);
	        /*-
	         * n1 = 3 * (X_a + Z_a^2) * (X_a - Z_a^2)
	         *    = 3 * X_a^2 - 3 * Z_a^4
	         */
	     } else {
	     	n0 = self.field_sqr(&self.x);
	     	n1 = self.lshift1_mod_quick(&n0,&field);
	     	ecsimple_log_trace!("mod_lshift_quick(n1 0x{:X},n0 0x{:X},p 0x{:X})",n1,n0,field);
	     	n0 = self.add_mod_quick(&n0,&n1,&field);
	     	ecsimple_log_trace!("mod_add_quick(n0 0x{:X},n0,n1 0x{:X},p 0x{:X})",n0,n1,field);
	     	n1 = self.field_sqr(&self.z);
	     	n1 = self.field_sqr(&n1);
	     	n1 = self.field_mul(&n1,&self.group.a);
	     	n1 = self.add_mod_quick(&n1,&n0,&field);
	     	ecsimple_log_trace!("mod_add_quick(n1 0x{:X},n1,n0 0x{:X},p 0x{:X})",n1,n0,field);
	     	/* n1 = 3 * X_a^2 + a_curve * Z_a^4 */
	     }

	     if self.z_is_one {
	     	n0 = self.y.clone();
	     	ecsimple_log_trace!("BN_copy(n0 0x{:X},a.y 0x{:X})",n0,self.y);
	     } else {
	     	n0 = self.field_mul(&self.y,&self.z);
	     }
	     retv.z = self.lshift1_mod_quick(&n0,&field);
	     ecsimple_log_trace!("mod_lshift_quick(r.z 0x{:X},n0 0x{:X},p 0x{:X})",retv.z,n0,field);
	     retv.z_is_one = false;
	     /* Z_r = 2 * Y_a * Z_a */

	     n3 = self.field_sqr(&self.y);
	     n2 = self.field_mul(&self.x,&n3);
	     n2 = self.lshift_mod_quick(&n2,2,&field);
	     ecsimple_log_trace!("mod_lshift_quick(n2 0x{:X},n2,0x2,p 0x{:X})",n2,field);
	     /* n2 = 4 * X_a * Y_a^2 */

	     n0 = self.lshift1_mod_quick(&n2,&field);
	     ecsimple_log_trace!("mod_lshift_quick(n0 0x{:X},n2 0x{:X},p 0x{:X})",n0,n2,field);
	     retv.x = self.field_sqr(&n1);
	     retv.x = self.sub_mod_quick(&retv.x,&n0,&field);
	     ecsimple_log_trace!("mod_sub_quick(r.x 0x{:X},r.x,n0 0x{:X},p 0x{:X})",retv.x,n0,field);
	     /* X_r = n1^2 - 2 * n2 */


	     n0 = self.field_sqr(&n3);
	     n3 = self.lshift_mod_quick(&n0,0x3,&field);
	     ecsimple_log_trace!("mod_lshift_quick(n3 0x{:X},n0 0x{:X},0x3,p 0x{:X})",n3,n0,field);
	     /* n3 = 8 * Y_a^4 */

	     n0 = self.sub_mod_quick(&n2,&retv.x,&field);
	     ecsimple_log_trace!("mod_sub_quick(n0 0x{:X},n2 0x{:X},r.x 0x{:X},p 0x{:X})",n0,n2,retv.x,field);
	     n0 = self.field_mul(&n1,&n0);
	     retv.y = self.sub_mod_quick(&n0,&n3,&field);
	     ecsimple_log_trace!("mod_sub_quick(r.y 0x{:X},n0 0x{:X},n3 0x{:X},p 0x{:X})",retv.y,n0,n3,field);
	     /* Y_r = n1 * (n2 - X_r) - n3 */

	     Ok(retv)
	 }

	 fn add(&self,b :&ECPrimePoint) -> Result<ECPrimePoint,Box<dyn Error>> {
	 	let mut retv :ECPrimePoint = ECPrimePoint::new(&self.group);
	 	let mut n0 :BigInt;
	 	let mut n1 :BigInt;
	 	let mut n2 :BigInt;
	 	let mut n3 :BigInt;
	 	let mut n4 :BigInt;
	 	let mut n5 :BigInt;
	 	let n6 :BigInt;
	 	let field :BigInt = self.group.p.clone();
	 	let zv :BigInt = zero();
	 	let ov :BigInt = one();
	 	let tv :BigInt = ov.clone() + ov.clone();
	 	if self.group != b.group {
	 		ecsimple_new_error!{ECPrimePointError,"not valid group point"}
	 	}
	 	if self == b {
	 		return self.dbl();
	 	} else if self.infinity {
	 		retv = b.clone();
	 		return Ok(retv);
	 	} else if b.infinity {
	 		retv= self.clone();
	 		return Ok(retv);
	 	}

	 	if b.z_is_one {
	 		n1 = self.x.clone();
	 		ecsimple_log_trace!("BN_copy(n1 0x{:X},a.x 0x{:X})",n1,self.x);
	 		n2 = self.y.clone();
	 		ecsimple_log_trace!("BN_copy(n2 0x{:X},a.y 0x{:X})",n2,self.y);
	 		/* n1 = X_a */
	 		/* n2 = Y_a */
	 	} else {
	 		n0 = self.field_sqr(&b.z);
	 		n1 = self.field_mul(&self.x,&n0);
	 		/* n1 = X_a * Z_b^2 */

	 		n0 = self.field_mul(&n0,&b.z);
	 		n2 = self.field_mul(&self.y,&n0);
	 		/* n2 = Y_a * Z_b^3 */
	 	}

	 	if self.z_is_one {
	 		n3 = b.x.clone();
	 		ecsimple_log_trace!("BN_copy(n3 0x{:X},b.x 0x{:X})",n3,b.x);
	 		n4 = b.y.clone();
	 		ecsimple_log_trace!("BN_copy(n4 0x{:X},b.y 0x{:X})",n4,b.y);
	 		/* n3 = X_b */
	 		/* n4 = Y_b */
	 	} else {
	 		n0 = self.field_sqr(&self.z);
	 		n3 = self.field_mul(&b.x,&n0);
	 		/* n3 = X_b * Z_a^2 */

	 		n0 = self.field_mul(&n0,&self.z);
	 		n4 = self.field_mul(&b.y,&n0);
	 		/* n4 = Y_b * Z_a^3 */
	 	}

	 	n5 = self.sub_mod_quick(&n1,&n3,&field);
	 	ecsimple_log_trace!("mod_sub_quick(n5 0x{:X},n1 0x{:X},n3 0x{:X},p 0x{:X})",n5,n1,n3,field);
	 	n6 = self.sub_mod_quick(&n2,&n4,&field);
	 	ecsimple_log_trace!("mod_sub_quick(n6 0x{:X},n2 0x{:X},n4 0x{:X},p 0x{:X})",n6,n2,n4,field);
	 	/* n5 = n1 - n3 */
	 	/* n6 = n2 - n4 */

	 	if n5 == zv {
	 		if n6 == zv {
	 			retv = self.dbl()?;
	 			ecsimple_log_trace!("a.x 0x{:X} a.y 0x{:X} a.z 0x{:X}",self.x,self.y,self.z);
	 			ecsimple_log_trace!("r.x 0x{:X} r.y 0x{:X} r.z 0x{:X}",retv.x,retv.y,retv.z);
	 			return Ok(retv);
	 		} else {
	 			retv.z = zv.clone();
	 			retv.z_is_one = false;
	 			ecsimple_log_trace!("r.z 0");
	 			return Ok(retv);
	 		}
	 	}

	 	n1 = self.add_mod_quick(&n1,&n3,&field);
	 	ecsimple_log_trace!("mod_add_quick(n1 0x{:X},n1,n3 0x{:X},p 0x{:X})",n1,n3,field);
	 	n2 = self.add_mod_quick(&n2,&n4,&field);
	 	ecsimple_log_trace!("mod_add_quick(n2 0x{:X},n2,n4 0x{:X},p 0x{:X})",n2,n4,field);
	 	/* 'n7' = n1 + n3 */
	 	/* 'n8' = n2 + n4 */

	 	if self.z_is_one && b.z_is_one {
	 		retv.z = n5.clone();
	 		ecsimple_log_trace!("BN_copy(r.z 0x{:X},n5 0x{:X})",retv.z,n5);
	 	} else {
	 		if self.z_is_one {
	 			n0 = b.z.clone();
	 			ecsimple_log_trace!("BN_copy(n0 0x{:X},b.z 0x{:X})",n0,b.z);
	 		} else if b.z_is_one {
	 			n0 = self.z.clone();
	 			ecsimple_log_trace!("BN_copy(n0 0x{:X},a.z 0x{:X})",n0,self.z);
	 		} else {
	 			n0 = self.field_mul(&self.z,&b.z);
	 		}

	 		retv.z = self.field_mul(&n0,&n5);
	 	}
	 	retv.z_is_one = false;
	 	/* Z_r = Z_a * Z_b * n5 */

	 	n0 = self.field_sqr(&n6);
	 	n4 = self.field_sqr(&n5);
	 	n3 = self.field_mul(&n1,&n4);
	 	retv.x = self.sub_mod_quick(&n0,&n3,&field);
	 	ecsimple_log_trace!("mod_sub_quick(r.x 0x{:X},n0 0x{:X},n3 0x{:X},p 0x{:X})",retv.x,n0,n3,field);
	 	/* X_r = n6^2 - n5^2 * 'n7' */

	 	n0 = self.lshift1_mod_quick(&retv.x,&field);
	 	ecsimple_log_trace!("mod_lshift_quick(n0 0x{:X},r.x 0x{:X},p 0x{:X})",n0,retv.x,field);
	 	n0 = self.sub_mod_quick(&n3,&n0,&field);
	 	ecsimple_log_trace!("mod_sub_quick(n0 0x{:X},n3 0x{:X},n0,p 0x{:X})",n0,n3,field);
	 	/* n9 = n5^2 * 'n7' - 2 * X_r */

	 	n0 = self.field_mul(&n0,&n6);
	 	n5 = self.field_mul(&n4,&n5);
	 	n1 = self.field_mul(&n2,&n5);
	 	n0 = self.sub_mod_quick(&n0,&n1,&field);
	 	ecsimple_log_trace!("mod_sub_quick(n0 0x{:X},n0,n1 0x{:X},p 0x{:X})",n0,n1,field);

	 	if (n0.clone() % tv.clone()) != zv {
	 		n0 = n0.clone() + field.clone();
	 		ecsimple_log_trace!("BN_add(n0 0x{:X},n0,p 0x{:X})",n0,field);
	 	}
	 	/* now  0 <= n0 < 2*p,  and n0 is even */

	 	retv.y = n0.clone() >> 1;
	 	ecsimple_log_trace!("BN_rshift1(r.y 0x{:X},n0 0x{:X})",retv.y,n0);
	 	/* Y_r = (n6 * 'n9' - 'n8' * 'n5^3') / 2 */

	 	Ok(retv)
	 }

	 pub fn eq_op(&self, other :&ECPrimePoint) -> bool {
	 	if self.group != other.group {
	 		return false;
	 	}
	 	if self.infinity != other.infinity {
	 		return false;
	 	}

	 	if self.infinity && other.infinity {
	 		return true;
	 	}

	 	if self.x != other.x {
	 		return false;
	 	}

	 	if self.y != other.y {
	 		return false;
	 	}

	 	if self.z != other.z {
	 		return false;
	 	}

	 	return true;
	 }

	 fn points_make_affine(&self,points :&mut [ECPrimePoint]) -> Result<(),Box<dyn Error>> {
	 	let mut tmp :BigInt;
	 	let mut tmp_z :BigInt;
	 	let mut prod_z :Vec<BigInt> = Vec::new();
	 	let zv :BigInt = zero();
	 	let mut idx :usize;
	 	if points.len() == 0 {
	 		return Ok(());
	 	}
	 	while prod_z.len() < points.len() {
	 		prod_z.push(zv.clone());
	 	}

	 	if points[0].z != zv {
	 		prod_z[0] = points[0].z.clone();
	 		ecsimple_log_trace!("BN_copy(prod_Z[0] 0x{:X},points[0].z 0x{:X})",prod_z[0],points[0].z);
	 	} else {
	 		prod_z[0] = self.field_set_to_one();
	 	}

	 	idx = 1;
	 	while idx < points.len() {
	 		if points[idx].z != zv {
	 			prod_z[idx] = self.field_mul(&prod_z[idx-1],&points[idx].z);
	 		} else {
	 			prod_z[idx] = prod_z[idx-1].clone();
	 			ecsimple_log_trace!("BN_copy(prod_Z[{}] 0x{:X},prod_Z[{}] 0x{:X})",idx,prod_z[idx],idx-1,prod_z[idx-1]);
	 		}
	 		idx += 1;
	 	}

	 	tmp = self.field_inv(&prod_z[prod_z.len() - 1]);

	 	tmp = self.field_encode(&tmp);
	 	tmp = self.field_encode(&tmp);

	 	idx = points.len() - 1;
	 	while idx > 0 {
	 		if points[idx].z != zv {
	 			tmp_z = self.field_mul(&prod_z[idx-1],&tmp);
	 			tmp = self.field_mul(&tmp,&points[idx].z);
	 			points[idx].z = tmp_z.clone();
	 		}
	 		idx -= 1;
	 	}

	 	if points[0].z != zv  {
	 		points[0].z = tmp.clone();
	 	}

	 	idx = 0;
	 	while idx < points.len() {
	 		if points[idx].z != zv {
	 			tmp = self.field_sqr(&points[idx].z);
	 			points[idx].x = self.field_mul(&points[idx].x,&tmp);
	 			tmp = self.field_mul(&tmp,&points[idx].z);
	 			points[idx].y = self.field_mul(&points[idx].y,&tmp);
	 			points[idx].z = self.field_set_to_one();
	 			points[idx].z_is_one = true;
	 		}
	 		idx += 1;
	 	}
	 	Ok(())
	 }

	 fn invert(&self) -> Result<ECPrimePoint,Box<dyn Error>> {
	 	let mut retv :ECPrimePoint = self.clone();
	 	let zv :BigInt = zero();
	 	let field :BigInt = self.group.p.clone();
	 	if retv.z == zv || retv.y == zv {
	 		return Ok(retv);
	 	}

	 	retv.y = bnusub(&field,&retv.y);
	 	ecsimple_log_trace!("BN_usub(p.y 0x{:X},group.field 0x{:X},p.y)",retv.y,field);
	 	Ok(retv)
	 }

	 fn blind_coordinate(&self) -> Result<ECPrimePoint,Box<dyn Error>> {
	 	let mut retv :ECPrimePoint = self.clone();
	 	let zv :BigInt = zero();
	 	let mut lambda :BigInt;
	 	let mut temp :BigInt;
	 	loop {
	 		lambda = ecsimple_private_rand_range(&self.group.p);
	 		if lambda != zv {
	 			break;
	 		}
	 	}

	 	lambda = self.field_encode(&lambda);
	 	ecsimple_log_trace!("field_encode");
	 	retv.z = self.field_mul(&retv.z,&lambda);
	 	ecsimple_log_trace!("field_mul");
	 	temp = self.field_sqr(&lambda);
	 	ecsimple_log_trace!("field_sqr");
	 	retv.x = self.field_mul(&retv.x,&temp);
	 	ecsimple_log_trace!("field_mul");
	 	temp = self.field_mul(&temp,&lambda);
	 	ecsimple_log_trace!("field_mul");
	 	retv.y = self.field_mul(&retv.y,&temp);
	 	ecsimple_log_trace!("field_mul");
	 	retv.z_is_one = false;

	 	Ok(retv)
	 }

	 fn point_set_infinity(&mut self) {
	 	self.z_is_one = false;
	 	self.z = zero();
	 	self.infinity = true;
	 	return;
	 }

	 pub fn mulex_op(&self,bn1 :&BigInt,bn2 :&BigInt) -> Result<ECPrimePoint,Box<dyn Error>> {
	 	let mut retv :ECPrimePoint = self.clone();

	 	let mut val_sub :Vec<Vec<ECPrimePoint>> = Vec::new();
	 	let mut wnaf_bits :Vec<i32> = Vec::new();
	 	let mut wnaf :Vec<Vec<u8>> = Vec::new();
	 	let mut curnaf :Vec<u8>;
	 	let mut bits :i32;
	 	let mut cv :Vec<ECPrimePoint>;
	 	let mut idx :usize;
	 	let mut tmp :ECPrimePoint;
	 	let mut jdx :usize;
	 	let mut affinepoints :Vec<ECPrimePoint>;
	 	let mut affidx :usize;
	 	let mut r_is_at_infinity :bool;
	 	let mut max_len :i32=0;
	 	let mut k :i32;
	 	let mut r_is_inversted :bool = false;
	 	(curnaf,bits) = self.get_wnaf_variable(bn2)?;
	 	wnaf_bits.push(bits);
	 	wnaf.push(curnaf.clone());
	 	ecsimple_log_trace!("scalars[0] 0x{:X}",bn2);
	 	ecsimple_debug_buffer_trace!(curnaf.as_ptr(),curnaf.len(),"wNAF wsize[0] 0x{:x}",wnaf_bits[0]);
	 	cv = Vec::new();
	 	cv.push(self.clone());
	 	val_sub.push(cv.clone());
	 	ecsimple_log_trace!("val_sub[0][0].X 0x{:X} val_sub[0][0].Y 0x{:X} val_sub[0][0].Z 0x{:X}",val_sub[0][0].x(),val_sub[0][0].y(),val_sub[0][0].z());



	 	(curnaf,bits) = self.get_wnaf_variable(bn1)?;
	 	wnaf_bits.push(bits);
	 	ecsimple_log_trace!("scalar 0x{:X}",bn1);
	 	ecsimple_debug_buffer_trace!(curnaf.as_ptr(),curnaf.len(),"wNAF wsize[1] 0x{:x}",wnaf_bits[1]);
	 	wnaf.push(curnaf.clone());
	 	cv = Vec::new();
	 	cv.push(ECPrimePoint::new(&self.group));
	 	val_sub.push(cv.clone());
	 	ecsimple_log_trace!("val_sub[1][0].X 0x{:X} val_sub[1][0].Y 0x{:X} val_sub[1][0].Z 0x{:X}",val_sub[1][0].x(),val_sub[1][0].y(),val_sub[1][0].z());

	 	idx = 0;
	 	while idx < wnaf_bits.len() {
	 		while val_sub[idx].len() < (1 << (wnaf_bits[idx] - 1)) as usize {
	 			val_sub[idx].push(ECPrimePoint::new(&self.group));
	 		}
	 		idx += 1;
	 	}

	 	idx = 0;
	 	while idx < wnaf.len() {
	 		if max_len < wnaf[idx].len() as i32 {
	 			max_len = wnaf[idx].len() as i32;
	 		}
	 		idx += 1;
	 	}

	 	idx = 0;
	 	while idx < val_sub.len() {
	 		if idx == 0 {
	 			ecsimple_log_trace!("[{}] copy points [{}]",idx,idx);
	 			val_sub[idx][0] = self.clone();
	 		} else {
	 			ecsimple_log_trace!("[{}] copy generator",idx);
	 			val_sub[idx][0] = ECPrimePoint::new(&self.group);
	 		}

	 		ecsimple_log_trace!("val_sub[{}][0].X 0x{:X} val_sub[{}][0].Y 0x{:X} val_sub[{}][0].Z 0x{:X}",idx,val_sub[idx][0].x(),idx,val_sub[idx][0].y(),idx,val_sub[idx][0].z());

	 		if wnaf[idx].len() > 1 {
	 			tmp = val_sub[idx][0].dbl()?;
	 			ecsimple_log_trace!("val_sub[{}][0].x 0x{:X} val_sub[{}][0].y 0x{:X} val_sub[{}][0].z 0x{:X}",idx,val_sub[idx][0].x,idx,val_sub[idx][0].y,idx,val_sub[idx][0].z);
	 			ecsimple_log_trace!("tmp.x 0x{:X} tmp.y 0x{:X} tmp.z 0x{:X}",tmp.x,tmp.y,tmp.z);
	 			jdx = 1;
	 			while jdx < (1 << (wnaf_bits[idx]-1)) as usize {
	 				val_sub[idx][jdx] = val_sub[idx][jdx-1].add(&tmp)?;
	 				ecsimple_log_trace!("val_sub[{}][{}].x 0x{:X} val_sub[{}][{}].y 0x{:X} val_sub[{}][{}].z 0x{:X}",idx,jdx-1,val_sub[idx][jdx-1].x,idx,jdx-1,val_sub[idx][jdx-1].y,idx,jdx-1,val_sub[idx][jdx-1].z);
	 				ecsimple_log_trace!("val_sub[{}][{}].x 0x{:X} val_sub[{}][{}].y 0x{:X} val_sub[{}][{}].z 0x{:X}",idx,jdx,val_sub[idx][jdx].x,idx,jdx,val_sub[idx][jdx].y,idx,jdx,val_sub[idx][jdx].z);
	 				jdx += 1;
	 			}

	 		}

	 		idx += 1;
	 	}

	 	idx = 0;
	 	affinepoints = Vec::new();
	 	while idx < val_sub.len() {
	 		jdx = 0;
	 		while jdx < val_sub[idx].len() {
	 			affinepoints.push(val_sub[idx][jdx].clone());
	 			jdx += 1;
	 		}
	 		idx += 1;
	 	}

	 	idx = 0;
	 	while idx < affinepoints.len() {
	 		ecsimple_log_trace!("val[{}].x 0x{:X} val[{}].y 0x{:X} val[{}].z 0x{:X}",idx,affinepoints[idx].x,idx,affinepoints[idx].y,idx,affinepoints[idx].z);
	 		idx += 1;
	 	}

	 	self.points_make_affine(&mut affinepoints)?;

	 	idx = 0;
	 	affidx = 0;
	 	while idx < val_sub.len() {
	 		jdx = 0;
	 		while jdx < val_sub[idx].len() {
	 			val_sub[idx][jdx] = affinepoints[affidx].clone();
	 			affidx += 1;
	 			jdx += 1;
	 		}
	 		idx += 1;
	 	}

	 	r_is_at_infinity = true;
	 	ecsimple_log_trace!("max_len {} wnaf.len() {}",max_len,wnaf.len());
	 	k = max_len -1 ;
	 	while k >= 0 {
	 		if ! r_is_at_infinity {
	 			retv = retv.dbl()?;
	 		}
	 		idx = 0;			
	 		while idx < wnaf.len() {
	 			if wnaf[idx].len() as i32 > k {
	 				let mut digit :u8 = wnaf[idx][k as usize];
	 				let mut is_neg :bool = false;
	 				ecsimple_log_trace!("wnaf[{}][{}] 0x{:x}",idx,k,digit);
	 				if digit != 0 {
	 					if (digit & 0x80) != 0 {
	 						is_neg = true;
	 						digit = 0xff - digit + 1;
	 					}
	 					ecsimple_log_trace!("digit [{}]",digit);

	 					if is_neg != r_is_inversted {
	 						if ! r_is_at_infinity {
	 							retv = retv.invert()?;
	 						}
	 						r_is_inversted = !r_is_inversted;
	 					}

	 					if r_is_at_infinity {
	 						ecsimple_log_trace!("digit [{}]",digit);
	 						retv = val_sub[idx][(digit >> 1) as usize].clone();
	 						retv = retv.blind_coordinate()?;
	 						r_is_at_infinity = false;
	 					} else {
	 						ecsimple_log_trace!("digit [{}]",digit);
	 						ecsimple_log_trace!("will get [{}][{}]",idx,(digit >> 1));
	 						retv = retv.add(&val_sub[idx][(digit >> 1) as usize])?;
	 					}
	 				}
	 			}
	 			idx += 1;
	 		}

	 		k -= 1;
	 	}

	 	if r_is_at_infinity {
	 		retv.point_set_infinity();
	 	} else {
	 		if r_is_inversted {
	 			retv = retv.invert()?;
	 		}
	 	}
	 	Ok(retv)
	 }

	 pub fn get_affine_points(&self) -> Result<(BigInt,BigInt),Box<dyn Error>> {
	 	let zv :BigInt = zero();
	 	let ov :BigInt = one();
	 	let x :BigInt;
	 	let y :BigInt;
	 	let z :BigInt;
	 	let z_ :BigInt;
	 	let z_1 :BigInt;
	 	let z_2 :BigInt;
	 	let z_3 :BigInt;
	 	if self.z == zv {
	 		ecsimple_new_error!{ECPrimePointError,"z == 0"}
	 	}

	 	ecsimple_log_trace!("point.X 0x{:X} point.Y 0x{:X} point.Z 0x{:X}",self.x,self.y,self.z);

	 	z  = self.field_decode(&self.z);
	 	z_ = z.clone();
	 	if z_ == ov {
	 		x = self.x.clone();
	 		y = self.y.clone();
	 	} else {
	 		z_1 = self.field_inv(&z_);
	 		z_2 = z_1.clone() * z_1.clone() % self.group.p.clone();
	 		ecsimple_log_trace!("BN_mod_sqr(Z_2 0x{:X},Z_1 0x{:X},group.field 0x{:X})",z_2,z_1,self.group.p);
	 		x = self.field_mul(&self.x,&z_2);
	 		z_3 = z_2.clone() * z_1.clone() % self.group.p.clone();
	 		y = self.field_mul(&self.y,&z_3);
	 	}

	 	ecsimple_log_trace!("x 0x{:X}",x);
	 	ecsimple_log_trace!("y 0x{:X}",y);
	 	Ok((x,y))
	 }

}

