if D:
    J=(D[0]&224)>>5
    R = D[:(1+(J in [U,V,a]))]
    D = D[(1+(J in [U,V,a])):]
    match J:
        case _ if J == U:
            K=P((R[0]&16)>>4);B=R[0]&15
            if B not in I(4):F=0
            G=R[0+1];H[B]=G
        case _ if J == V:
            K=P((R[0]&16)>>4);B=R[0]&15
            if B not in I(4):F=0
            if not K:L=(R[0+1]&240)>>4;H[B]+=H[L]
            else:G=R[0+1];H[B]+=G
        case _ if J == a:
            K=P((R[0]&16)>>4);B=R[0]&15
            if B not in I(4):F=0
            if not K:L=(R[0+1]&240)>>4;H[B]^=H[L]
            else:G=R[0+1];H[B]^=G
        case _ if J == W:
            B=R[0]&15
            if B not in I(4):F=0
            if(R[0]&16)>>4!=0:F=0
            G=H[B]
            if G!=0:F=0
        case _ if J == X:
            B=R[0]&15
            if B not in I(4):F=0
            if(R[0]&16)>>4!=0:F=0
            G=Q.pop();H[B]=G;
        case _ if J == Y:
            B=R[0]&15
            if B not in I(4):F=0
            if(R[0]&16)>>4!=0:F=0
            G=H[B];Q.append(G);
        case _ if J == Z:
            B=R[0]&15
            if B not in I(4):F=0
            if(R[0]&16)>>4!=0:F=0
            if len(M)==0:M=input().encode()
            G=M[0];M=M[1:];H[B]=G;
        case _ if J == b:
            pass
        case _:
            F=0