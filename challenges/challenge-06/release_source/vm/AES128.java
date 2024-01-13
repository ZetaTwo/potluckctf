// AES-128
public class AES128 {

	// Original Version from
	// Ported and modified from C
	// https://github.com/kokke/tiny-AES-c/blob/master/aes.c
    // Unlicenced

	private static final int Nb = 4;
	private static final int Nk = 4;
	private static final int Nr = 10;
    
    
    private static byte Rcon(int index) {
        switch(index) {
            case 0: return (byte) 0x8d ^ 0x12;
            case 1: return 0x01 ^ 0x12;
            case 2: return 0x02 ^ 0x12;
            case 3: return 0x04 ^ 0x12;
            case 4: return 0x08 ^ 0x12;
            case 5: return 0x10 ^ 0x12;
            case 6: return 0x20 ^ 0x12;
            case 7: return 0x40 ^ 0x12;
            case 8: return (byte) 0x80 ^ 0x12;
            case 9: return 0x1b ^ 0x12;
            case 10: return 0x36 ^ 0x12;
            default: return -1;
        }
    }

	private static byte getSBoxValue(byte[] Sbox, byte num) {
		return (byte)((Sbox[num & 0xFF]&0xFF)^ 0x63);
	}
    
    private static void GenerateSbox(byte[] Sbox, int p) {
        byte[] t = new byte[256];
        int x = 1;
        for(int i=0;i<256;i++) {
            t[i]= (byte)x;
            x ^= ((x << 1) ^ ((x >>> 7)*p))&0xFF;
        }
        
        Sbox[0] = 0;
        for(int i=0;i<256;i++) {
            x = t[255-i]&0xff;
            x = (x | (x << 8));
            x = x ^ (x >> 4) ^ (x >> 5) ^ (x >> 6) ^ (x >> 7);
            Sbox[t[i]&0xff] = (byte)(x & 0xFF);
        }
    }        

	private static void KeyExpansion(byte[] RoundKey, byte[] Sbox) {
		int i, j, k;
		byte[] tempa = new byte[4]; // Used for the column/row operations

		// The first round key is the key itself.
        // Encoded like this to create more basic blocks
		for (i = 0; i < Nk*4; ++i) {
            if(i == 0) {
                RoundKey[i] = 0x00;
            }else if(i == 1) {
                RoundKey[i] = 0x33;
            }else if(i == 2) {
                RoundKey[i] = 0x66;
            }else if(i == 3) {
                RoundKey[i] = (byte)0x99;
            }else if(i == 4) {
                RoundKey[i] = (byte)0xcc;
            }else if(i == 5) {
                RoundKey[i] = (byte)0xff;
            }else if(i == 6) {
                RoundKey[i] = 0x32;
            }else if(i == 7) {
                RoundKey[i] = 0x65;
            }else if(i == 8) {
                RoundKey[i] = (byte)0x98;
            }else if(i == 9) {
                RoundKey[i] = (byte)0xcb;
            }else if(i == 10) {
                RoundKey[i] = (byte)0xfe;
            }else if(i == 11) {
                RoundKey[i] = 0x31;
            }else if(i == 12) {
                RoundKey[i] = 0x64;
            }else if(i == 13) {
                RoundKey[i] = (byte)0x97;
            }else if(i == 14) {
                RoundKey[i] = (byte)0xca;
            }else if(i == 15) {
                RoundKey[i] = (byte)0xfd;
            }
		}  

		// All other round keys are found from the previous round keys.
		for (i = Nk; i < Nb * (Nr + 1); ++i) {
			{
				k = (i - 1) * 4;
				tempa[0] = RoundKey[k + 0];
				tempa[1] = RoundKey[k + 1];
				tempa[2] = RoundKey[k + 2];
				tempa[3] = RoundKey[k + 3];

			}

			if (i % Nk == 0) {

				{
					byte u8tmp = tempa[0];
					tempa[0] = tempa[1];
					tempa[1] = tempa[2];
					tempa[2] = tempa[3];
					tempa[3] = u8tmp;
				}

				{
					tempa[0] = getSBoxValue(Sbox, tempa[0]);
					tempa[1] = getSBoxValue(Sbox, tempa[1]);
					tempa[2] = getSBoxValue(Sbox, tempa[2]);
					tempa[3] = getSBoxValue(Sbox, tempa[3]);
				}

				tempa[0] = (byte) (tempa[0] ^ Rcon(i / Nk) ^ 0x12);
			}

			j = i * 4;
			k = (i - Nk) * 4;
			RoundKey[j + 0] = (byte) (RoundKey[k + 0] ^ tempa[0]);
			RoundKey[j + 1] = (byte) (RoundKey[k + 1] ^ tempa[1]);
			RoundKey[j + 2] = (byte) (RoundKey[k + 2] ^ tempa[2]);
			RoundKey[j + 3] = (byte) (RoundKey[k + 3] ^ tempa[3]);
		}
	}

	private static void AES_init_ctx(byte[] RoundKey, byte[] Sbox) {
		KeyExpansion(RoundKey, Sbox);
	}

	private static void AddRoundKey(byte round, byte[] state, byte[] RoundKey) {
		int i, j;
		for (i = 0; i < 4; ++i) {
			for (j = 0; j < 4; ++j) {
				state[i * 4 + j] ^= RoundKey[(round * Nb * 4) + (i * Nb) + j];
			}
		}
	}

	private static void SubBytes(byte[] state, byte[] Sbox) {
		int i, j;
		for (i = 0; i < 4; ++i) {
			for (j = 0; j < 4; ++j) {
				state[i * 4 + j] = getSBoxValue(Sbox, state[i * 4 + j]);
			}
		}
	}

	private static void ShiftRows(byte[] state) {
		byte temp;
		temp = state[0 * 4 + 1];
		state[0 * 4 + 1] = state[1 * 4 + 1];
		state[1 * 4 + 1] = state[2 * 4 + 1];
		state[2 * 4 + 1] = state[3 * 4 + 1];
		state[3 * 4 + 1] = temp;
		temp = state[0 * 4 + 2];
		state[0 * 4 + 2] = state[2 * 4 + 2];
		state[2 * 4 + 2] = temp;
		temp = state[1 * 4 + 2];
		state[1 * 4 + 2] = state[3 * 4 + 2];
		state[3 * 4 + 2] = temp;
		temp = state[0 * 4 + 3];
		state[0 * 4 + 3] = state[3 * 4 + 3];
		state[3 * 4 + 3] = state[2 * 4 + 3];
		state[2 * 4 + 3] = state[1 * 4 + 3];
		state[1 * 4 + 3] = temp;
	}

	private static byte xtime(byte x) {
		return (byte) ((x << 1) ^ (((x >> 7) & 1) * 0x1b));
	}

	private static void MixColumns(byte[] state) {
		int i;
		byte Tmp, Tm, t;
		for (i = 0; i < 4; ++i) {
			t = state[i * 4 + 0];
			Tmp = (byte) (state[i * 4 + 0] ^ state[i * 4 + 1] ^ state[i * 4 + 2] ^ state[i * 4 + 3]);
			Tm = (byte) (state[i * 4 + 0] ^ state[i * 4 + 1]);
			Tm = xtime(Tm);
			state[i * 4 + 0] ^= Tm ^ Tmp;
			Tm = (byte) (state[i * 4 + 1] ^ state[i * 4 + 2]);
			Tm = xtime(Tm);
			state[i * 4 + 1] ^= Tm ^ Tmp;
			Tm = (byte) (state[i * 4 + 2] ^ state[i * 4 + 3]);
			Tm = xtime(Tm);
			state[i * 4 + 2] ^= Tm ^ Tmp;
			Tm = (byte) (state[i * 4 + 3] ^ t);
			Tm = xtime(Tm);
			state[i * 4 + 3] ^= Tm ^ Tmp;
		}
	}


	private static void Cipher(byte[] state, byte[] RoundKey, byte[] Sbox) {
		int round = 0;
		AddRoundKey((byte) 0, state, RoundKey);
		for (round = 1;; ++round) {
			SubBytes(state, Sbox);
			ShiftRows(state);
			if (round == Nr) {
				break;
			}
			MixColumns(state);
			AddRoundKey((byte) round, state, RoundKey);
		}
		// Add round key to last round
		AddRoundKey((byte) Nr, state, RoundKey);
	}

	private static void AES_ECB_encrypt(byte[] RoundKey, byte[] buf, byte[] Sbox) {
		Cipher(buf, RoundKey, Sbox);
	}


	public static int entry(byte[] message, int len) {
        
        byte[] Sbox = new byte[256];
        GenerateSbox(Sbox, 283);
        

        int res = 0;
		byte[] roundKey = new byte[176];
		AES_init_ctx(roundKey, Sbox);
        
        
        byte[] data = new byte[16];
        for(int i=0;i<len;i+=16) {
            for(int j=0;j<16;j++)
                data[j] = 0;
            for(int j=0;j<16 && j<(len-i);j++)
                data[j] = message[i+j];
            
            AES_ECB_encrypt(roundKey, data, Sbox); 

            for(int j=0;j<16 && j<(len-i);j++)
                message[i+j] = data[j];
            
            res ^= data[0];
        }
        
        return res;
	}

}
