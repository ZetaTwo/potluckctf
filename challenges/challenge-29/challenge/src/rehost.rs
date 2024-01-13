use crate::constants;

#[inline(always)]
fn can_send() -> bool {
    let byte: u64 =
        unsafe { core::ptr::read_volatile(core::ptr::from_exposed_addr(constants::CHAN_ADDR)) };
    byte == 0xffff_ffff_ffff_ffff
}

#[inline(always)]
fn can_recv() -> bool {
    let byte: u64 =
        unsafe { core::ptr::read_volatile(core::ptr::from_exposed_addr(constants::CHAN_ADDR)) };
    byte != 0xffff_ffff_ffff_ffff
}

#[inline(always)]
fn write_buf(data: &[u8]) {
    unsafe { 
        let addr = core::ptr::from_exposed_addr_mut(constants::CHAN_ADDR);
        core::ptr::write_volatile(addr, data);
    }
}

#[inline(always)]
fn read_buf() -> [u8; 8] {
    let ret = unsafe {
        let addr = core::ptr::from_exposed_addr_mut(constants::CHAN_ADDR);
        core::ptr::read_volatile(addr)
    };
    reset();
    ret
}

#[inline(always)]
fn reset() {
    unsafe {
        let addr = core::ptr::from_exposed_addr_mut(constants::CHAN_ADDR);
        core::ptr::write_volatile(addr, 0xffff_ffff_ffff_ffffu64);
    }
}

#[allow(dead_code)]
#[inline(never)]
pub fn recv_flag() -> [u8; 48] {
    unsafe {
         let addr = core::ptr::from_exposed_addr(constants::FLAG_ADDR);
         core::ptr::read_volatile(addr)
    }
}

#[allow(dead_code)]
#[inline(always)]
pub fn send_flag() {
    unsafe {
        let addr = core::ptr::from_exposed_addr_mut(constants::FLAG_ADDR);
        core::ptr::write_volatile(addr, constants::FLAG);
    }
}

#[inline(never)]
pub fn send_data(data: &[u8]) {
    assert!(data.len() % 8 == 0);

    let mut cur = 0;

    while cur < data.len() {
        while !can_send() {}

        write_buf(&data[cur..cur+8]);
        cur += 8;
    }
}

#[inline(never)]
pub fn recv_data<const N: usize>() -> [u8; N] {
    assert!(N % 8 == 0);

    let mut cur = 0;
    let mut ret = [0; N];
    while cur < N {
        while !can_recv() {}

        ret[cur..cur+8].copy_from_slice(&read_buf());
        cur += 8
    }
    ret
}

