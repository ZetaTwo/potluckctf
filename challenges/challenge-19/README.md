# ezrop
Author: [Shayan Alinejad (Carixo)](https://github.com/CarixoHD)

Category: Pwn

Difficulty: Hard

## Description
Ez ez ez ez. Super ezrop. Would even call it babyrop, but a bit harder... This is revenge!.

```
nc xxx yyy
```

[chall](./ezrop)

## Proposed solution
Use the gets function. The rdi after gets is always the same, so change the rdi to "%p" by running gets after the first iteration. Then use printf to leak pointers (the rdi is still the same, so its %p). Then jump back to main and overflow and do ret2libc.

[solve.py](./solve.py)
