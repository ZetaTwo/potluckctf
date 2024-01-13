use num_bigint::{BigInt,Sign};
use num_traits::{zero,one};
use crate::*;
#[allow(unused_imports)]
use crate::logger::*;
use std::error::Error;
use crate::randop::*;
use lazy_static::lazy_static;

ecsimple_error_class!{ECUtilsError}

fn bn_is_odd(a :&BigInt) -> bool {
    let zv :BigInt = zero();
    let ov :BigInt = one();
    let tv :BigInt = ov.clone() + ov.clone();

    if (a % &tv) == zv {
        return false;
    }
    return true;
}

pub (crate) fn format_bigint_as_order(bn2 :&[u8], order :&BigInt) -> BigInt {
	let obits :i64 = get_max_bits(order);
    ecsimple_log_trace!("order bits 0x{:x}",obits);
	let mut bs :Vec<u8>;
	bs = bn2.to_vec();
	if (8 * bs.len()) > (obits as usize) {
		bs = bs[0..(((obits as usize) +7) >> 3)].to_vec();
	}
    ecsimple_log_trace!("dgst_len 0x{:x}",bs.len());
    ecsimple_debug_buffer_trace!(bs.as_ptr(),bs.len(),"dgst 0x{:x}",bs.len());

	let mut retv :BigInt = BigInt::from_bytes_be(Sign::Plus,&bs);
    ecsimple_log_trace!("dgst_len 0x{:x} 0x{:X}",bs.len(),retv);
	if bs.len() * 8 > (obits as usize) {
		retv = retv >> (8 - obits & 0x7);
	}
	return retv;
}

pub (crate) fn get_bit_set(bn :&BigInt,i :i32) -> i32 {
	let mut retv :i32 = 0;
	let ov :BigInt = one();
	let zv :BigInt = zero();
	if (bn & (ov << i)) != zv {
		retv = 1;
	}
	return retv;
}

pub (crate) fn nmod(a :&BigInt,m :&BigInt) -> BigInt {
	let mut retv :BigInt;
	let zv :BigInt = zero();
	retv = a % m;
	if retv < zv {
		retv += m;
	}
	return retv;
}

fn verify_mod_sqrt(retv :&BigInt,ac :&BigInt,p :&BigInt) -> Result<BigInt,Box<dyn Error>> {
    let cv :BigInt;
    cv = retv.clone() * retv.clone() % p.clone();
    if cv != ac.clone() {
        ecsimple_new_error!{ECUtilsError,"check 0x{:X} for mod_sqrt(0x{:X},0x{:X}) error",retv,ac,p}
    }
    return Ok(retv.clone());
}


lazy_static ! {
    static ref KRONTAB :Vec<i32> = {
        let  retv :Vec<i32> = vec![0,1,0,-1,0,-1,0,1];
        retv
    };
}

fn get_lsw(v :&BigInt, mask :u32) -> u32 {
    let vecs :Vec<u8>;
    let mut retv :u32=0;
    (_,vecs) = v.to_bytes_le();
    let mut idx :usize = 0;
    while idx < vecs.len() && idx < 4 {
        retv |= (vecs[idx] as u32) << (idx * 8);
        idx += 1;
    }
    return retv & mask;
}

#[allow(unused_variables)]
#[allow(unused_assignments)]
#[allow(non_snake_case)]
fn kronecker_value(a :&BigInt,b :&BigInt) -> i32 {
    let mut ret :i32;
    let mut A :BigInt;
    let mut B :BigInt;
    let zv :BigInt = zero();
    let ov :BigInt = one();
    let mut i :i32;
    let mut tmp :BigInt;

    A = a.clone();
    B = b.clone();
    ecsimple_log_trace!("A 0x{:X} B 0x{:X}",A,B);

    /*
     * Kronecker symbol, implemented according to Henri Cohen,
     * "A Course in Computational Algebraic Number Theory"
     * (algorithm 1.4.10).
     */
     if B == zv {
        if A == ov {
            ret = 1;
        } else {
            ret = 0;
        }
        ecsimple_log_trace!("ret {}",ret);
        return ret;
    }

    if !bn_is_odd(&A) && !bn_is_odd(&B) {
        ret = 0;
        ecsimple_log_trace!("ret 0");
        return ret;
    }

    i = 0;
    while get_bit_set(&B,i) == 0 {
        i += 1;
    }
    ecsimple_log_trace!("B 0x{:X} i {}",B,i);
    B = B.clone() >> i;
    ecsimple_log_trace!("B 0x{:X}",B);

    if (i & 1) != 0 {
        ret = KRONTAB[get_lsw(&A,7) as usize];
        ecsimple_log_trace!("ret {} tab[BN_lsw(0x{:X})&7 = 0x{:x}]", ret, A,get_lsw(&A,7));
    } else {
        ret = 1;
        ecsimple_log_trace!("ret 1");
    }

    if B < zv {
        B = -B.clone();
        if A < zv {
            ret = -ret;
            ecsimple_log_trace!("A net ret {}",ret);
        }
    }

    loop {
        if A == zv {
            if B != ov {
                ret = 0;
            }
            ecsimple_log_trace!("B 0x{:X} ret {}",B,ret);
            return ret;
        }

        i = 0;
        while get_bit_set(&A,i) == 0{
            i += 1;
        }
        ecsimple_log_trace!("A 0x{:X} i {}",A,i);
        A = A.clone() >> i;
        ecsimple_log_trace!("A 0x{:X}",A);

        if (i & 1) != 0 {
            ecsimple_log_trace!("ret {} = ret {} * tab[BN_lsw(0x{:X})&7 = 0x{:x}]",ret * KRONTAB[get_lsw(&B,7) as usize], ret,B,get_lsw(&B,7));
            ret = ret * KRONTAB[get_lsw(&B,7) as usize];
        }

        let mut rv :u32;

        if A < zv {
            rv = get_lsw(&A,0xffffffff);
            rv = !rv;
        } else {
            rv = get_lsw(&A,0xffffffff) & get_lsw(&B,0xffffffff) & 0x2;
        }

        if rv != 0 {
            let mut negv :String=format!("0");
            if A < zv {
                negv = format!("1");
            }
            ecsimple_log_trace!("A->neg {} A 0x{:X} B 0x{:X}",negv,A,B);
            ret = -ret;
        }

        B = nmod(&B,&A);
        ecsimple_log_trace!("nnmod(B 0x{:X},B,A 0x{:X})",B,A);

        tmp = A.clone();
        A = B.clone();
        B = tmp.clone();
        ecsimple_log_trace!("A 0x{:X} B 0x{:X}",A,B);
        if B < zv {
            B = -B;
        }
    }
}

#[allow(non_snake_case)]
pub fn mod_sqrt(ac :&BigInt,p :&BigInt) -> Result<BigInt,Box<dyn Error>> {
    let mut retv :BigInt = zero();
    let ov :BigInt = one();
    let zv :BigInt = zero();
    let tv :BigInt = ov.clone() + ov.clone();
    let A :BigInt;
    let mut b :BigInt;
    let mut q :BigInt;
    let mut t :BigInt;
    let mut x :BigInt = zv.clone();
    let mut y :BigInt;
    let mut e :i32;
    let mut vecs :Vec<u8>;
    let mut i :i32;
    let mut r :i32;
    if (p % tv.clone()) == zv || p == &ov {
        if p == &tv {
            if get_bit_set(ac,0) == 0 {
                retv = zv.clone();
            } else {
                retv = ov.clone();
            }
            return Ok(retv);
        }
        ecsimple_new_error!{ECUtilsError,"p 0x{:X} not valid prime",p}
    }

    if ac == &zv || ac == &ov {
        retv = ac.clone();
        ecsimple_log_trace!("ret 0x{:X}",retv);
        return Ok(retv);
    }

    A = nmod(ac,p);
    ecsimple_log_trace!("BN_nnmod(A 0x{:X},a 0x{:X},p 0x{:X})",A,ac,p);
    e = 1;
    while get_bit_set(p,e) == 0 {
        e += 1;
    }
    ecsimple_log_trace!("e 0x{:x}",e);

    if e == 1 {
        q = p.clone() >> 2;
        ecsimple_log_trace!("BN_rshift(q 0x{:X},p 0x{:X},2)",q,p);
        /*to set plus*/
        (_,vecs) = q.to_bytes_le();
        q = BigInt::from_bytes_le(Sign::Plus,&vecs);
        q += ov.clone();
        ecsimple_log_trace!("BN_add_word(q 0x{:X},1)",q);
        retv = A.modpow(&q,p);
        ecsimple_log_trace!("BN_mod_exp(ret 0x{:X},A 0x{:X},q 0x{:X},p 0x{:X})",retv,A,q,p);
        return verify_mod_sqrt(&retv,&A,p);
    }
    if e == 2 {
        /*-
         * |p| == 5  (mod 8)
         *
         * In this case  2  is always a non-square since
         * Legendre(2,p) = (-1)^((p^2-1)/8)  for any odd prime.
         * So if  a  really is a square, then  2*a  is a non-square.
         * Thus for
         *      b := (2*a)^((|p|-5)/8),
         *      i := (2*a)*b^2
         * we have
         *     i^2 = (2*a)^((1 + (|p|-5)/4)*2)
         *         = (2*a)^((p-1)/2)
         *         = -1;
         * so if we set
         *      x := a*b*(i-1),
         * then
         *     x^2 = a^2 * b^2 * (i^2 - 2*i + 1)
         *         = a^2 * b^2 * (-2*i)
         *         = a*(-i)*(2*a*b^2)
         *         = a*(-i)*i
         *         = a.
         *
         * (This is due to A.O.L. Atkin,
         * Subject: Square Roots and Cognate Matters modulo p=8n+5.
         * URL: https://listserv.nodak.edu/cgi-bin/wa.exe?A2=ind9211&L=NMBRTHRY&P=4026
         * November 1992.)
         */


         /* t := 2*a */
         t = (A.clone() << 1) % p.clone();
         ecsimple_log_trace!("BN_mod_lshift1_quick(t 0x{:X},A 0x{:X},p 0x{:X})",t,A,p);
         /* b := (2*a)^((|p|-5)/8) */
         q = p.clone() >> 3;
         ecsimple_log_trace!("BN_rshift(q 0x{:X},p 0x{:X},0x3)",q,p);
         /*to set plus*/
         (_,vecs) = q.to_bytes_le();
         q = BigInt::from_bytes_le(Sign::Plus,&vecs);

         b = t.modpow(&q,p);
         ecsimple_log_trace!("BN_mod_exp(b 0x{:X},t 0x{:X},q 0x{:X},p 0x{:X})",b,t,q,p);

         /* y := b^2 */
         y = b.modpow(&tv,p);
         ecsimple_log_trace!("BN_mod_sqr(y 0x{:X},b 0x{:X},p 0x{:X})",y,b,p);

         /* t := (2*a)*b^2 - 1 */
         t = t.clone() * y.clone() % p.clone();
         ecsimple_log_trace!("BN_mod_mul(t 0x{:X},t,y 0x{:X},p 0x{:X})",t,y,p);
         t -= ov.clone();
         ecsimple_log_trace!("BN_sub_word(t 0x{:X},1)",t);

         /* x = a*b*t */
         x = A.clone() * b.clone() % p.clone();
         ecsimple_log_trace!("BN_mod_mul(x 0x{:X},A 0x{:X},b 0x{:X},p 0x{:X})",x,A,b,p);
         x = x.clone() * t.clone() % p.clone();
         ecsimple_log_trace!("BN_mod_mul(x 0x{:X},x,t 0x{:X},p 0x{:X})",x,t,p);
         retv = x.clone();
         ecsimple_log_trace!("BN_copy(ret 0x{:X},x 0x{:X})",retv,x);
         return verify_mod_sqrt(&retv,&A,p);
     }

     q = p.clone();
     ecsimple_log_trace!("BN_copy(q 0x{:X},p 0x{:X})",q,p);
     (_,vecs) = q.to_bytes_le();
     q = BigInt::from_bytes_le(Sign::Plus,&vecs);

     i = 2;
     loop {
        if i < 22 {
            vecs = Vec::new();
            vecs.push(i as u8);
            y = BigInt::from_bytes_le(Sign::Plus,&vecs);
        } else {
            y = ecsimple_rand_bits(get_max_bits(p) as u64,0,0);
            y = nmod(&y,p);
            if y == zv {
                vecs = Vec::new();
                vecs.push(i as u8);
                y = BigInt::from_bytes_le(Sign::Plus,&vecs);                
            }
        }

        ecsimple_log_trace!("before BN_kronecker(y 0x{:X},q 0x{:X})",y,q);
        r = kronecker_value(&y,&q);
        ecsimple_log_trace!("r ({})=BN_kronecker(y 0x{:X},q 0x{:X})",r,y,q);

        if r < -1 {
            ecsimple_new_error!{ECUtilsError,"error kronecker_value {}",r}
        } else if r == 0 {
            ecsimple_new_error!{ECUtilsError,"not prime for p 0x{:X}",p}
        }

        i += 1;
        if r != 1 || i >= 82{
            break;
        }
    }
    ecsimple_log_trace!("r = {}",r);

    if r != -1 {
        ecsimple_new_error!{ECUtilsError,"too many iterators for mod_sqrt"}
    }

    q = q.clone() >> e;
    ecsimple_log_trace!("BN_rshift(q 0x{:X},q,e 0x{:x})",q,e);

    y = y.clone().modpow(&q,p);
    ecsimple_log_trace!("BN_mod_exp(y 0x{:X},y,q 0x{:X},p 0x{:X})",y,q,p);
    if y == ov {
        ecsimple_new_error!{ECUtilsError,"p 0x{:X} is not prime",p}
    }

    /*-
     * Now we know that (if  p  is indeed prime) there is an integer
     * k,  0 <= k < 2^e,  such that
     *
     *      a^q * y^k == 1   (mod p).
     *
     * As  a^q  is a square and  y  is not,  k  must be even.
     * q+1  is even, too, so there is an element
     *
     *     X := a^((q+1)/2) * y^(k/2),
     *
     * and it satisfies
     *
     *     X^2 = a^q * a     * y^k
     *         = a,
     *
     * so it is the square root that we are looking for.
     */

    /* t := (q-1)/2  (note that  q  is odd) */
    t = q.clone() >> 1;
    ecsimple_log_trace!("BN_rshift1(t 0x{:X},q 0x{:X})",t,q);

    /* x := a^((q-1)/2) */
    if t == zv {
        t = nmod(&A,p);
        ecsimple_log_trace!("BN_nnmod(t 0x{:X},A 0x{:X},p 0x{:X})",t,A,p);
        if t == zv {
            retv = zv.clone();
            return Ok(retv);
        } else if x == ov {
            return Ok(retv);
        }
    } else {
        x = A.clone().modpow(&t,p);
        ecsimple_log_trace!("BN_mod_exp(x 0x{:X},A 0x{:X},t 0x{:X},p 0x{:X})",x,A,t,p);
        if x == zv {
            retv = zv.clone();
            return Ok(retv);
        }
    }

    /* b := a*x^2  (= a^q) */
    b = (x.clone() * x.clone()) % p.clone();
    ecsimple_log_trace!("BN_mod_sqr(b 0x{:X},x 0x{:X},p 0x{:X})",b,x,p);
    b = (b.clone() * A.clone()) % p.clone();
    ecsimple_log_trace!("BN_mod_mul(b 0x{:X},b,A 0x{:X},p 0x{:X})",b,A,p);
    x = (x.clone() * A.clone()) % p.clone();
    ecsimple_log_trace!("BN_mod_mul(x 0x{:X},x,A 0x{:X},p 0x{:X})",x,A,p);

    loop {
        /*-
         * Now  b  is  a^q * y^k  for some even  k  (0 <= k < 2^E
         * where  E  refers to the original value of  e,  which we
         * don't keep in a variable),  and  x  is  a^((q+1)/2) * y^(k/2).
         *
         * We have  a*b = x^2,
         *    y^2^(e-1) = -1,
         *    b^2^(e-1) = 1.
         */
        if b == ov {
            retv = x.clone();
            ecsimple_log_trace!("BN_copy(ret 0x{:X},x 0x{:X})",retv,x);
            return verify_mod_sqrt(&retv,&A,p);
        }

        i = 1;
        while i < e {
            if i == 1 {
                t = b.clone() * b.clone() % p.clone();
                ecsimple_log_trace!("BN_mod_sqr(t 0x{:X},b 0x{:X},p 0x{:X})",t,b,p);
            } else {
                t = t.clone() * t.clone() % p.clone();
                ecsimple_log_trace!("BN_mod_mul(t 0x{:X},t,t,p 0x{:X})",t,p);
            }
            if t == ov {
                break;
            }
            i +=1;
        }

        if i >= e {
            ecsimple_new_error!{ECUtilsError,"no sqrt for a [0x{:X}] for p [0x{:X}]",ac,p}
        }

        /* t := y^2^(e - i - 1) */
        t = y.clone();
        let mut j :i32;
        j = e - i - 1;
        while j > 0 {
            t = t.clone() * t.clone() % p.clone();
            ecsimple_log_trace!("BN_mod_sqr(t 0x{:X},t,p 0x{:X})",t,p);
            j -= 1;
        }
        y = t.clone() * t.clone() % p.clone();
        ecsimple_log_trace!("BN_mod_mul(y 0x{:X},t 0x{:X},t,p 0x{:X})",y,t,p);
        x = x.clone() * t.clone() % p.clone();
        ecsimple_log_trace!("BN_mod_mul(x 0x{:X},x,t 0x{:X},p 0x{:X})",x,t,p);
        b = b.clone() * y.clone() % p.clone();
        ecsimple_log_trace!("BN_mod_mul(b 0x{:X},b,y 0x{:X},p 0x{:X})",b,y,p);
        e = i;
    }

}

pub (crate) fn get_wnaf_bits(bn :&BigInt) -> i32 {
    let bbits :i64 = get_max_bits(bn);
    if bbits >= 2000 {
        return 6;
    } else if bbits >= 800 {
        return 5;
    } else if bbits >= 300 {
        return 4;
    } else if bbits >= 70 {
        return 3;
    } else if bbits >= 20 {
        return 2;
    }
    return 1;
}

pub (crate) fn wnaf_value(bn :&BigInt,w :i32) -> Result<Vec<u8>,Box<dyn Error>> {
    let mut retv :Vec<u8> = Vec::new();
    let zv :BigInt = zero();
    let ov :BigInt = one();
    if w < 1 || w > 7 {
        ecsimple_new_error!{ECUtilsError,"w {} < 1 || > 7", w};
    }
    let bit :BigInt = ov.clone() << w;
    let next_bit :BigInt = bit.clone() << 1;
    let mask :BigInt = next_bit.clone() - ov.clone();
    let mut window_val :BigInt;
    let mut j :i32 = 0;
    let lenv :i32;
    window_val = bn.clone() & mask.clone();
    lenv = get_max_bits(bn) as i32;
    while window_val != zv || (j+ w + 1) < lenv {
        let mut digit : BigInt = zv.clone();
        if (window_val.clone() & ov.clone()) != zv {
            if (window_val.clone() & bit.clone()) != zv {
                digit = window_val.clone() - next_bit.clone();
                if (j + w + 1) >= lenv {
                    digit = window_val.clone() & (mask.clone() >> 1);
                }
            } else {
                digit = window_val.clone();
            }
            if digit.clone() <= - bit.clone() || digit.clone() >=bit.clone() ||  (digit.clone() & ov.clone()) == zv {
                ecsimple_new_error!{ECUtilsError,"internal error on digit"}
            }
            window_val -= digit.clone();
        }
        let (_,vecs) = digit.to_bytes_le();
        if digit >= zv {
            retv.push(vecs[0]);     
        } else {
            retv.push((0xff - vecs[0] + 1) as u8);
        }
        
        j += 1;
        window_val = window_val.clone() >> 1;
        if (bn.clone() & (ov.clone() << (j + w))) != zv  {
            window_val += bit.clone();
        }

        if window_val > next_bit.clone() {
            ecsimple_new_error!{ECUtilsError,"window_val 0x{:X} > next_bit 0x{:X}", window_val,next_bit}
        }
    }

    if j > (lenv + 1) {
        ecsimple_new_error!{ECUtilsError,"j {} > lenv {} + 1",j,lenv}
    }
    Ok(retv)
}

pub (crate) fn bnusub(anum :&BigInt,bnum :&BigInt) -> BigInt {
    let retv :BigInt;
    if anum > bnum {
        retv = anum - bnum;
    } else {
        let curv :BigInt = anum - bnum;
        let mut curvecs :Vec<u8>;
        let mut maskvecs :Vec<u8> = Vec::new();
        let mut resvecs :Vec<u8> = Vec::new();
        let mut idx :usize;
        (_ , curvecs) = curv.to_bytes_le();
        while (curvecs.len() % 8) != 0 {
            curvecs.push(0);
        }

        while maskvecs.len() < curvecs.len() {
            maskvecs.push(0xff);
            resvecs.push(0);
        }
        idx = 0;
        while idx < maskvecs.len() {
            resvecs[idx] = maskvecs[idx] ^ curvecs[idx];
            idx += 1;
        }
        resvecs[0] += 1;
        retv = BigInt::from_bytes_le(Sign::Plus,&resvecs);
    }

    return retv;
}
