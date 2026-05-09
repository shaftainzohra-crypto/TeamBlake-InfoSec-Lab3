#AI tools have been for debugging and for writing the correct output format in a compact way. The algorithm has been implemented by the author following
#the indications of FIPS PUB 180-4
import numpy as np
import hashlib
import os
class SHA512:
    #CONSTANTS
    w = 64
    K = [int("428a2f98d728ae22",16), int("7137449123ef65cd",16), int("b5c0fbcfec4d3b2f",16), int("e9b5dba58189dbbc",16),
     int("3956c25bf348b538",16), int("59f111f1b605d019",16), int("923f82a4af194f9b",16), int("ab1c5ed5da6d8118",16),
     int("d807aa98a3030242",16), int("12835b0145706fbe",16), int("243185be4ee4b28c",16), int("550c7dc3d5ffb4e2",16),
     int("72be5d74f27b896f",16), int("80deb1fe3b1696b1",16), int("9bdc06a725c71235",16), int("c19bf174cf692694",16),
     int("e49b69c19ef14ad2",16), int("efbe4786384f25e3",16), int("0fc19dc68b8cd5b5",16), int("240ca1cc77ac9c65",16),
     int("2de92c6f592b0275",16), int("4a7484aa6ea6e483",16), int("5cb0a9dcbd41fbd4",16), int("76f988da831153b5",16),
     int("983e5152ee66dfab",16), int("a831c66d2db43210",16), int("b00327c898fb213f",16), int("bf597fc7beef0ee4",16),
     int("c6e00bf33da88fc2",16), int("d5a79147930aa725",16), int("06ca6351e003826f",16), int("142929670a0e6e70",16),
     int("27b70a8546d22ffc",16), int("2e1b21385c26c926",16), int("4d2c6dfc5ac42aed",16), int("53380d139d95b3df",16),
     int("650a73548baf63de",16), int("766a0abb3c77b2a8",16), int("81c2c92e47edaee6",16), int("92722c851482353b",16),
     int("a2bfe8a14cf10364",16), int("a81a664bbc423001",16), int("c24b8b70d0f89791",16), int("c76c51a30654be30",16),
     int("d192e819d6ef5218",16), int("d69906245565a910",16), int("f40e35855771202a",16), int("106aa07032bbd1b8",16),
     int("19a4c116b8d2d0c8",16), int("1e376c085141ab53",16), int("2748774cdf8eeb99",16), int("34b0bcb5e19b48a8",16),
     int("391c0cb3c5c95a63",16), int("4ed8aa4ae3418acb",16), int("5b9cca4f7763e373",16), int("682e6ff3d6b2b8a3",16),
     int("748f82ee5defb2fc",16), int("78a5636f43172f60",16), int("84c87814a1f0ab72",16), int("8cc702081a6439ec",16),
     int("90befffa23631e28",16), int("a4506cebde82bde9",16), int("bef9a3f7b2c67915",16), int("c67178f2e372532b",16),
     int("ca273eceea26619c",16), int("d186b8c721c0c207",16), int("eada7dd6cde0eb1e",16), int("f57d4f7fee6ed178",16),
     int("06f067aa72176fba",16), int("0a637dc5a2c898a6",16), int("113f9804bef90dae",16), int("1b710b35131c471b",16),
     int("28db77f523047d84",16), int("32caab7b40c72493",16), int("3c9ebe0a15c9bebc",16), int("431d67c49c100d4c",16),
     int("4cc5d4becb3e42b6",16), int("597f299cfc657e2a",16), int("5fcb6fab3ad6faec",16), int("6c44198c4a475817",16)
     ]
    H_0 = [int("6a09e667f3bcc908",16), int("bb67ae8584caa73b",16), int("3c6ef372fe94f82b",16), int("a54ff53a5f1d36f1",16), int("510e527fade682d1",16), int("9b05688c2b3e6c1f",16), int("1f83d9abfb41bd6b",16), int("5be0cd19137e2179",16)]

    # FUNCTIONS
    def __Ch(x,y,z):
        return (x & y)^( (~ x & 0xFFFFFFFFFFFFFFFF) & z)

    def __Maj(x,y,z):
        return (x & y)^( x & z)^(y & z)

    def __SHR(x,n):
        return x>>n

    def __SHL(x,n):
        return (x<<n)& 0xFFFFFFFFFFFFFFFF

    def __ROTR(x,n):
        if(n<0 or n>=SHA512.w):
            exit("Invalid length for n")
        return SHA512.__SHR(x,n)|SHA512.__SHL(x,SHA512.w-n)

    def __big_sigma_512_0(x):
        rotr28 = SHA512.__ROTR(x,28)
        rotr34 = SHA512.__ROTR(x,34)
        rotr39 = SHA512.__ROTR(x,39)
        return rotr28^rotr34^rotr39

    def __big_sigma_512_1(x):
        rotr14 = SHA512.__ROTR(x,14)
        rotr18 = SHA512.__ROTR(x,18)
        rotr41 = SHA512.__ROTR(x,41)
        return rotr14^rotr18^rotr41

    def __small_sigma_512_0(x):
        rotr1 = SHA512.__ROTR(x,1)
        rotr8 = SHA512.__ROTR(x,8)
        shr7 = SHA512.__SHR(x,7)
        return rotr1^rotr8^shr7

    def __small_sigma_512_1(x):
        rotr19 = (SHA512.__ROTR(x,19))
        rotr61 = SHA512.__ROTR(x,61)
        shr6 = SHA512.__SHR(x,6)
        return rotr19^rotr61^shr6



    #SECURE HASH ALGORITHM
    #PREPROCESSING
    def __padding(M, previous_len_bits=0):
        l = previous_len_bits + len(M)
        l_bin = f"{l:0128b}"

        k = (896 - (l + 1)) % 1024

        pad = M + "1"
        pad += "0" * k
        pad += l_bin

        return pad

    def __parsing(pad):
        size = 1024
        blocks = []
        for i in range(int(len(pad)/size)):
            blocks.append(pad[i*size:(i+1)*size])
        return blocks
    def __get_word_block(block):
        size_block = 1024
        words = []
        for i in range(int(size_block/SHA512.w)):
            words.append(int(block[i*SHA512.w:(i+1)*SHA512.w],2))
        return words
    def __get_all_words(blocks):
        size_block = 1024
        words = np.array([[]])
        for i in range(int(len(blocks)/size_block)):
            for j in range(int(size_block/SHA512.w)):
                words=[i][j*SHA512.w:(1+j)*SHA512.w]
        return words
    def __preprocessing(M, initial_state=None, previous_len_bits = 0):
        if isinstance(M, str):
            M_bytes = M.encode('utf-8')
        else:
            M_bytes = M
        M_bits = "".join(f"{b:08b}" for b in M_bytes)
        if(initial_state == None):
            H_0 = SHA512.H_0.copy()
        else:
            H_0 = initial_state
        padded_M = SHA512.__padding(M_bits,previous_len_bits)
        parsed_padded_M = SHA512.__parsing(padded_M)
        return H_0,parsed_padded_M

    #HASH COMPUTATION
    def hash_computation(M,initial_state=None, previous_len_bits = 0):
        if not isinstance(M, (bytes, bytearray)):
            raise TypeError("Input must be byte array only!")
        H,parsed_padded_M = SHA512.__preprocessing(M,initial_state,previous_len_bits)
        N = len(parsed_padded_M)
        for i in range(0,N):
            W = SHA512.__get_word_block(parsed_padded_M[i])
            for t in range(16,80):
                W.append((SHA512.__small_sigma_512_1(W[t-2]) + W[t-7]+ SHA512.__small_sigma_512_0(W[t-15]) + W[t-16]) & 0xFFFFFFFFFFFFFFFF)
            a = H[0]
            b = H[1]
            c = H[2]
            d = H[3]
            e = H[4]
            f = H[5]
            g = H[6]
            h = H[7]
            for t in range(80):
                T_1 = (h + SHA512.__big_sigma_512_1(e) + SHA512.__Ch(e,f,g)+ SHA512.K[t] + W[t]) & 0xFFFFFFFFFFFFFFFF
                T_2 = (SHA512.__big_sigma_512_0(a)+ SHA512.__Maj(a,b,c)) & 0xFFFFFFFFFFFFFFFF
                h = g
                g = f
                f = e
                e = (d + T_1)& 0xFFFFFFFFFFFFFFFF
                d = c
                c = b
                b = a
                a = (T_1 + T_2)& 0xFFFFFFFFFFFFFFFF
            H[0] = (a + H[0])& 0xFFFFFFFFFFFFFFFF
            H[1] = (b + H[1])& 0xFFFFFFFFFFFFFFFF
            H[2] = (c + H[2])& 0xFFFFFFFFFFFFFFFF
            H[3] = (d + H[3])& 0xFFFFFFFFFFFFFFFF
            H[4] = (e + H[4])& 0xFFFFFFFFFFFFFFFF
            H[5] = (f + H[5])& 0xFFFFFFFFFFFFFFFF
            H[6] = (g + H[6])& 0xFFFFFFFFFFFFFFFF
            H[7] = (h + H[7])& 0xFFFFFFFFFFFFFFFF
        output_bytes =   b"".join(h.to_bytes(8, 'big') for h in H)
        return output_bytes

# TEST AREA
if __name__ == "__main__":
    count = 0
    for _ in range(100):
        test_data = os.urandom(np.random.randint(1, 1000))
        # messaggio = b"80000000000000000000000000000000"
        my = SHA512.hash_computation(test_data)
        my_hex = my.hex()
        real_hex = hashlib.sha512(test_data).hexdigest()
        #real = ":".join(real_hex[i:i+2] for i in range(0, len(real_hex), 2))
        if (my_hex == real_hex):
            count = count + 1
    print("Randomized interoperability test: success rate = " + str(count) + "/100")