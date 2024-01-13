import sys


def KSA(key, S):
    len_key = 8
    j = 0
    for i in range(0x100):
        S[i] = i
    for i in range(0x100):
        j = (j + (S[i]&0xFF) + (key[i % len_key]&0xFF)) % 0x100
        S[i], S[j] = S[j], S[i]



def PRGA(S, plaintext, l):
    i = 0;
    j = 0;
    for n in range(l):
        i = (i + 1) % 0x100
        j = (j + (S[i]&0xFF)) % 0x100
        S[i], S[j] = S[j], S[i]
        rnd = S[((S[i]&0xFF) + (S[j]&0xFF)) % 0x100]
        plaintext[n] = (rnd ^ plaintext[n])&0xFF


def rc4(key,plaintext, l):
    buffer = [0]*256
    KSA(key, buffer)
    PRGA(buffer, plaintext, l)
    


def main():
    inpFile = sys.argv[1]
    outFile = sys.argv[2]
    
    with open(inpFile, "rb") as f:
        data = list(f.read())
        l = len(data)
        key = [0]*8
        key[0] = 0x01
        key[1] = 0x02
        key[2] = 0x03
        key[3] = 0x04
        key[4] = 0x05
        key[5] = 0x06
        key[6] = 0x07
        key[7] = 0x08
        rc4(key, data, l)
        
        with open(outFile, "wb") as f2:
            f2.write(bytes(data))
    
    
if __name__ == '__main__':
    main()
    
