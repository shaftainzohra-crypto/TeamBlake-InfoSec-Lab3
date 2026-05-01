#AI tools have been for debugging and for writing the correct output format in a compact way. The algorithm has been implemented by the author following
#the indications of FIPS PUB 180-4
import numpy as np
import hashlib
import os
class SHA256:
    #CONSTANTS
    w = 32
    K = [int("428a2f98",16), int("71374491",16), int("b5c0fbcf",16), int("e9b5dba5",16), int("3956c25b",16), int("59f111f1",16), int("923f82a4",16), int("ab1c5ed5",16),
         int("d807aa98",16), int("12835b01",16), int("243185be",16), int("550c7dc3",16), int("72be5d74",16), int("80deb1fe",16), int("9bdc06a7",16), int("c19bf174",16),
         int("e49b69c1",16), int("efbe4786",16), int("0fc19dc6",16), int("240ca1cc",16), int("2de92c6f",16), int("4a7484aa",16), int("5cb0a9dc",16), int("76f988da",16),
         int("983e5152",16), int("a831c66d",16), int("b00327c8",16), int("bf597fc7",16), int("c6e00bf3",16), int("d5a79147",16), int("06ca6351",16), int("14292967",16),
         int("27b70a85",16), int("2e1b2138",16), int("4d2c6dfc",16), int("53380d13",16), int("650a7354",16), int("766a0abb",16), int("81c2c92e",16), int("92722c85",16),
         int("a2bfe8a1",16), int("a81a664b",16), int("c24b8b70",16), int("c76c51a3",16), int("d192e819",16), int("d6990624",16), int("f40e3585",16), int("106aa070",16),
         int("19a4c116",16), int("1e376c08",16), int("2748774c",16), int("34b0bcb5",16), int("391c0cb3",16), int("4ed8aa4a",16), int("5b9cca4f",16), int("682e6ff3",16),
         int("748f82ee",16), int("78a5636f",16), int("84c87814",16), int("8cc70208",16), int("90befffa",16), int("a4506ceb",16), int("bef9a3f7",16), int("c67178f2",16)
         ]
    H_0 = [int("6a09e667",16), int("bb67ae85",16), int("3c6ef372",16), int("a54ff53a",16), int("510e527f",16), int("9b05688c",16), int("1f83d9ab",16), int("5be0cd19",16)]

    # FUNCTIONS
    def Ch(x,y,z):
        return (x & y)^( (~ x & 0xFFFFFFFF) & z)

    def Maj(x,y,z):
        return (x & y)^( x & z)^(y & z)

    def SHR(x,n):
        return x>>n

    def SHL(x,n):
        return (x<<n)& 0xFFFFFFFF

    def ROTR(x,n):
        if(n<0 or n>=SHA256.w):
            exit("Invalid length for n")
        return SHA256.SHR(x,n)|SHA256.SHL(x,SHA256.w-n)

    def big_sigma_256_0(x):
        rotr2 = SHA256.ROTR(x,2)
        rotr13 = SHA256.ROTR(x,13)
        rotr22 = SHA256.ROTR(x,22)
        return rotr2^rotr13^rotr22

    def big_sigma_256_1(x):
        rotr6 = SHA256.ROTR(x,6)
        rotr11 = SHA256.ROTR(x,11)
        rotr25 = SHA256.ROTR(x,25)
        return rotr6^rotr11^rotr25

    def small_sigma_256_0(x):
        rotr7 = SHA256.ROTR(x,7)
        rotr18 = SHA256.ROTR(x,18)
        shr3 = SHA256.SHR(x,3)
        return rotr7^rotr18^shr3

    def small_sigma_256_1(x):
        rotr17 = SHA256.ROTR(x,17)
        rotr19 = SHA256.ROTR(x,19)
        shr10 = SHA256.SHR(x,10)
        return rotr17^rotr19^shr10

    #SECURE HASH ALGORITHM
    #PREPROCESSING
    def padding(M):
        l = len(M)
        l_bin = f"{l:064b}"
        k = (448 - (l+1))%512
        pad = M + "1"
        for i in range(k):
            pad = pad + "0"
        pad = pad + l_bin
        return pad

    def parsing(pad):
        size = 512
        blocks = []
        for i in range(int(len(pad)/size)):
            blocks.append(pad[i*size:(i+1)*size])
        return blocks
    def get_word_block(block):
        size_block = 512
        size_word = 32
        words = []
        for i in range(int(size_block/size_word)):
            words.append(int(block[i*size_word:(i+1)*size_word],2))
        return words
    def get_all_words(blocks):
        size_block = 512
        size_word = 32
        words = np.array([[]])
        for i in range(int(len(blocks)/size_block)):
            for j in range(int(size_block/size_word)):
                words=[i][j*size_word:(1+j)*size_word]
        return words
    def preprocessing(M, initial_state=None):
        if isinstance(M, str):
            M_bytes = M.encode('utf-8')
        else:
            M_bytes = M
        M_bits = "".join(f"{b:08b}" for b in M_bytes)
        if(initial_state == None):
            H_0 = SHA256.H_0.copy()
        else:
            H_0 = initial_state
        padded_M = SHA256.padding(M_bits)
        parsed_padded_M = SHA256.parsing(padded_M)
        return H_0,parsed_padded_M

    #HASH COMPUTATION
    def hash_computation(M,initial_state=None):
        H,parsed_padded_M = SHA256.preprocessing(M,initial_state)
        N = len(parsed_padded_M)
        for i in range(0,N):
            W = SHA256.get_word_block(parsed_padded_M[i])
            for t in range(16,64):
                W.append((SHA256.small_sigma_256_1(W[t-2]) + W[t-7]+ SHA256.small_sigma_256_0(W[t-15]) + W[t-16]) & 0xFFFFFFFF)
            a = H[0]
            b = H[1]
            c = H[2]
            d = H[3]
            e = H[4]
            f = H[5]
            g = H[6]
            h = H[7]
            for t in range(64):
                T_1 = (h + SHA256.big_sigma_256_1(e) + SHA256.Ch(e,f,g)+ SHA256.K[t] + W[t])& 0xFFFFFFFF
                T_2 = (SHA256.big_sigma_256_0(a)+ SHA256.Maj(a,b,c)) & 0xFFFFFFFF
                h = g
                g = f
                f = e
                e = (d + T_1)& 0xFFFFFFFF
                d = c
                c = b
                b = a
                a = (T_1 + T_2)& 0xFFFFFFFF
            H[0] = (a + H[0])& 0xFFFFFFFF
            H[1] = (b + H[1])& 0xFFFFFFFF
            H[2] = (c + H[2])& 0xFFFFFFFF
            H[3] = (d + H[3])& 0xFFFFFFFF
            H[4] = (e + H[4])& 0xFFFFFFFF
            H[5] = (f + H[5])& 0xFFFFFFFF
            H[6] = (g + H[6])& 0xFFFFFFFF
            H[7] = (h + H[7])& 0xFFFFFFFF
        output_hex = f"{H[0]:08x}"+f"{H[1]:08x}"+f"{H[2]:08x}"+f"{H[3]:08x}"+f"{H[4]:08x}"+f"{H[5]:08x}"+f"{H[6]:08x}"+f"{H[7]:08x}"
        #return ":".join(output_hex[i:i+2] for i in range(0, len(output_hex), 2))
        return output_hex

# TEST AREA
if __name__ == "__main__":
    count = 0
    for _ in range(100):
        test_data = os.urandom(np.random.randint(1, 1000))
       # messaggio = b"80000000000000000000000000000000"
        my = SHA256.hash_computation(test_data)
        real_hex = hashlib.sha256(test_data).hexdigest()
       # real = ":".join(real_hex[i:i+2] for i in range(0, len(real_hex), 2))
        if (my == real):
            count = count + 1
    print(count)
