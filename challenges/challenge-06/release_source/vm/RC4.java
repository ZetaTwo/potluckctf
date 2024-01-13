/**
 * RC4 Implementation - Merged Functions Example
 */
public class RC4 {
    
	private static void swap(byte[] array, int a, int b) {
		byte tmp = array[a];
		array[a] = array[b];
		array[b] = tmp;
	}

	private static void KSA(byte[] key, byte[] S) {
	    int len_key = 8;
	    int j = 0;

	    for(int i = 0; i < 0x100; i++) {
	        S[i] = (byte) i;
        }

	    for(int i = 0; i < 0x100; i++) {
	        j = (j + (S[i]&0xFF) + (key[i % len_key]&0xFF)) % 0x100;
	        swap(S, i, j);
	    }
	}

	private static void PRGA(byte[] S, byte[] plaintext, int len) {
	    int i = 0;
	    int j = 0;

	    for(int n = 0; n < len; n++) {
	        i = (i + 1) % 0x100;
	        j = (j + (S[i]&0xFF)) % 0x100;
	        swap(S, i, j);
	        int rnd = S[((S[i]&0xFF) + (S[j]&0xFF)) % 0x100];
	        plaintext[n] = (byte) (rnd ^ plaintext[n]);
	    }

	}
	
	// key len = 8
	private static void rc4(byte[] key, byte[] plaintext, int len) {
		byte[] buffer = new byte[0x100];
	    KSA(key, buffer);
	    PRGA(buffer, plaintext, len);
	    return;
	}
    
    public static int entry(byte[] data, int len) {
        byte[] key = new byte[8];
        // Secret Key for JS Transfer - encoded this way to make more basic blocks
        for(int i=0;i<8;i++) {
            key[i] = (byte)(i+1);
        }
        rc4(key, data, len);
        return 0;
    }
    
}