//! `intrinsics` implements the intrinsics needed by rustc. Because we don't need
//! float support, we won't use them (or maybe we will and people have to hook
//! these ....

#[no_mangle]
fn __hexagon_memcpy_likely_aligned_min32bytes_mult8bytes(dst: *mut u8, src: *const u8, len: usize) -> isize {
    memcpy(dst, src, len)
}

#[no_mangle]
fn bcmp(dst: *mut u8, src: *const u8, len: usize) -> isize {
    for x in 0..=(len-1) {
        let src_byte: i8 = unsafe { src.add(x).read() as _ };
        let dst_byte: i8 = unsafe { dst.add(x).read() as _ };
        if src_byte != dst_byte { return (dst_byte - src_byte) as isize; }
    }
    0
}

#[no_mangle]
fn memcmp(dst: *mut u8, src: *const u8, len: usize) -> isize {
    for x in 0..=(len-1) {
        let src_byte: i8 = unsafe { src.add(x).read() as _ };
        let dst_byte: i8 = unsafe { dst.add(x).read() as _ };
        if src_byte != dst_byte { return (dst_byte - src_byte) as isize; }
    }
    0
}

#[no_mangle]
fn memcpy(dst: *mut u8, src: *const u8, len: usize) -> isize {
    for x in 0..=(len-1) {
        unsafe {
            dst.add(x).write(src.add(x).read());
        }
    }
    0
}

#[no_mangle]
fn memset(dst: *mut u8, b: u8, len: usize) -> isize {
    for x in 0..=(len-1) {
        unsafe {
            dst.add(x).write(b);
        }
    }
    0
}

#[no_mangle]
fn __hexagon_adddf3() {
    unimplemented!();
}

#[no_mangle]
fn __hexagon_divsi3() {
    unimplemented!();
}

#[no_mangle]
fn __hexagon_umoddi3() {
    unimplemented!();
}

#[no_mangle]
fn __hexagon_umodsi3() {
    unimplemented!();
}

#[no_mangle]
fn __hexagon_divsf3() {
    unimplemented!();
}

#[no_mangle]
fn __hexagon_muldf3() {
    unimplemented!();
}

#[no_mangle]
fn __hexagon_divdf3() {
    unimplemented!();
}

#[no_mangle]
fn __hexagon_udivdi3() {
    unimplemented!();
}

#[no_mangle]
fn __hexagon_udivsi3() {
    unimplemented!();
}
