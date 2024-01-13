J=(D[A]&224)>>5
match J:
    case _ if J == U:
        K=P((D[A]&16)>>4);B=D[A]&15
        if B not in I(4):E(F);C(1)
        G=D[A+1];H[B]=G
        A+=2
    case _ if J == V:
        K=P((D[A]&16)>>4);B=D[A]&15
        if B not in I(4):E(F);C(1)
        if not K:L=(D[A+1]&240)>>4;H[B]+=H[L]
        else:G=D[A+1];H[B]+=G
        A+=2
    case _ if J == a:
        K=P((D[A]&16)>>4);B=D[A]&15
        if B not in I(4):E(F);C(1)
        if not K:L=(D[A+1]&240)>>4;H[B]^=H[L]
        else:G=D[A+1];H[B]^=G
        A += 2
    case _ if J == W:
        B=D[A]&15
        if B not in I(4):E(F);C(1)
        if(D[A]&16)>>4!=0:E(F);C(1)
        G=H[B]
        if G!=0:E(F);C(1)
        A+=1
    case _ if J == X:
        B=D[A]&15
        if B not in I(4):E(F);C(1)
        if(D[A]&16)>>4!=0:E(F);C(1)
        G=Q.pop();H[B]=G;A+=1
    case _ if J == Y:
        B=D[A]&15
        if B not in I(4):E(F);C(1)
        if(D[A]&16)>>4!=0:E(F);C(1)
        G=H[B];Q.append(G);A+=1
    case _ if J == Z:
        B=D[A]&15
        if B not in I(4):E(F);C(1)
        if(D[A]&16)>>4!=0:E(F);C(1)
        G=M[0];M=M[1:];H[B]=G;A+=1
    case _ if J == b:
        B=D[A]&15
        if B not in I(4):E(F);C(1)
        if(D[A]&16)>>4!=0:E(F);C(1)
        G=H[B];E(chr(G),end='');A+=1
    case _:
        E(F);C(1)