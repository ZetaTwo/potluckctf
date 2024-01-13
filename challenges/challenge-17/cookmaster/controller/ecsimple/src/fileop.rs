
use crate::{ecsimple_new_error,ecsimple_error_class};
use std::error::Error;
use std::io::{Read};


ecsimple_error_class!{ECFileOpError}

pub struct RandFile {
	f : std::fs::File,
	fname :String,
}

impl RandFile {
	pub fn new(name :&str) -> Result<RandFile,Box<dyn Error>> {
		let ores = std::fs::File::open(name);
		if ores.is_err() {
			let e = ores.err().unwrap();
			ecsimple_new_error!{ECFileOpError,"open {} error {:?}",name,e}
		}
		let f = ores.unwrap();
		Ok(RandFile {
			f : f,
			fname : format!("{}",name),
		})
	}
}

impl rand_core::CryptoRng  for RandFile {
}

impl rand_core::RngCore for RandFile {
	fn next_u32(&mut self) -> u32 {
		let mut buf = [0u8; 4];
		let ores = self.f.read(&mut buf);
		if ores.is_err() {
			let e = ores.err().unwrap();
			panic!("read [{}] error[{:?}]",self.fname,e);
		}
		let cnt = ores.unwrap();
		if cnt != 4 {
			panic!("can not read [{}]", self.fname);
		}
		let mut retv :u32 = 0;
		for i in 0..buf.len() {
			retv |= (buf[i] as u32) << (i * 8);
		}
		retv
	}

	fn next_u64(&mut self) -> u64 {
		let mut buf = [0u8; 8];
		let ores = self.f.read(&mut buf);
		if ores.is_err() {
			let e = ores.err().unwrap();
			panic!("read [{}] error[{:?}]",self.fname,e);
		}
		let cnt = ores.unwrap();
		if cnt != 8 {
			panic!("can not read [{}]", self.fname);
		}
		let mut retv :u64 = 0;
		for i in 0..buf.len() {
			retv |= (buf[i] as u64) << (i * 8);
		}
		retv
	}

	fn fill_bytes(&mut self, dest: &mut [u8]) {
		let ores = self.f.read(dest);
		if ores.is_err() {
			let e = ores.err().unwrap();
			panic!("read [{}] error[{:?}]",self.fname,e);
		}
		let cnt = ores.unwrap();
		if cnt != dest.len() {
			panic!("can not read [{}]", self.fname);	
		}
		return;
	}

	fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(),rand_core::Error> {
		let ores = self.f.read(dest);
		if ores.is_err() {
			let e = ores.err().unwrap();
			let e2 = ECFileOpError::create(&format!("read {} error {:?}",self.fname,e));
			return Err(rand_core::Error::new(e2));
		}
		let cnt = ores.unwrap();
		if cnt != dest.len() {
			let e2 = ECFileOpError::create(&format!("read {} cnt {} != {}",self.fname,cnt,dest.len()));
			return Err(rand_core::Error::new(e2));
		}
		Ok(())
	}
}
