p = ~-(-~(()==()))** 521
c = 5437994412763609312287807471880072729673281757441094697938294966650919649177305854023158593494881613184278290778097252426658538133266876768217809554790925406
F.<x> = ZZ[]

W = diagonal_matrix([2^176,1], sparse=False)
lll = (matrix([[c,1],[p,0]])*W).LLL() / W

for i in range(-99,99):
    for j in range(-99,99):
        sumXY, prodXY = vector([i, j]) * lll
        if 0 < sumXY < 256^22 and 0 < prodXY < 256^44:
            roots = (x * (sumXY - x) - prodXY).roots()
            if roots:
                print(i, j, [int(a).to_bytes(22, 'big') for a,b in roots])
                # potluck{y0u_c4n_hav3_y0ur_cak3_&_ea7_1t_t0o}
