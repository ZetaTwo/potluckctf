/*
 * ====================================================
 * Copyright (C) 1993 by Sun Microsystems, Inc. All rights reserved.
 *
 * Developed at SunPro, a Sun Microsystems, Inc. business.
 * Permission to use, copy, modify, and distribute this
 * software is freely granted, provided that this notice
 * is preserved.
 * ====================================================
 */
/*
 * modf(double x, double *iptr)
 * return fraction part of x, and return x's integral part in *iptr.
 * Method:
 *	Bit twiddling.
 *
 * Exception:
 *	No exception.
 */


#include <math.h>
#include <stdint.h>



typedef union
{
  double value;
  struct
  {
    uint32_t msw;
    uint32_t lsw;
  } parts;
  uint64_t word;
} ieee_double_shape_type;


/* Get all in one, efficient on 64-bit machines.  */
#ifndef EXTRACT_WORDS64
# define EXTRACT_WORDS64(i,d)					\
do {								\
  ieee_double_shape_type gh_u;					\
  gh_u.value = (d);						\
  (i) = gh_u.word;						\
} while (0)
#endif

/* Get all in one, efficient on 64-bit machines.  */
#ifndef INSERT_WORDS64
# define INSERT_WORDS64(d,i)					\
do {								\
  ieee_double_shape_type iw_u;					\
  iw_u.word = (i);						\
  (d) = iw_u.value;						\
} while (0)
#endif


static const double one = 1.0;
double
modf(double x, double *iptr)
{
	int64_t i0;
	int32_t j0;
	EXTRACT_WORDS64(i0,x);
	j0 = ((i0>>52)&0x7ff)-0x3ff;	/* exponent of x */
	if(j0<52) {			/* integer part in x */
	    if(j0<0) {			/* |x|<1 */
		/* *iptr = +-0 */
		INSERT_WORDS64(*iptr,i0&UINT64_C(0x8000000000000000));
		return x;
	    } else {
		uint64_t i = UINT64_C(0x000fffffffffffff)>>j0;
		if((i0&i)==0) {		/* x is integral */
		    *iptr = x;
		    /* return +-0 */
		    INSERT_WORDS64(x,i0&UINT64_C(0x8000000000000000));
		    return x;
		} else {
		    INSERT_WORDS64(*iptr,i0&(~i));
		    return x - *iptr;
		}
	    }
	} else { /* no fraction part */
	    *iptr = x*one;
	    /* We must handle NaNs separately.  */
	    if (j0 == 0x400 && (i0 & UINT64_C(0xfffffffffffff)))
	      return x*one;
	    INSERT_WORDS64(x,i0&UINT64_C(0x8000000000000000));	/* return +-0 */
	    return x;
	}
}