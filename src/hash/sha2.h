
//Function declaration
uint32_t rotr(uint32_t x, int n);
unsigned long long int simplePower(int a, int b);
void sha256(uint8_t* salt, int saltlen, FILE* fp, unsigned long long int fs, uint8_t* buffer);


// Right rotation
uint32_t rotr(uint32_t x, int n) {
    return (x >> n % 32) | (x << (32-n) % 32);
}

// Computes natural number exponents
unsigned long long int simplePower(int a, int b)
{
    unsigned long long int ans = 1;
    for(int i = 0; i < b; i++)
    {
        ans *= a;
    }
    return ans;
}

// Filesize to bytes, given 8-byte buffer, big endian, from the right.
void nFilesize_bytes(unsigned long long int fs, uint8_t* buffer)
{
    int length = 0;     //Number of bytes required to store the number.

    fs *= 8;            //Number of bits of the input
    //Determine the number of bytes needed.
    for(int i = 1; i <= 8; i++)
    {
        if(fs < simplePower(256,i))
        {
            length = i;
            break;
        }
    }

    uint8_t remainder = 0;
    //Assignment
    for(int i = 0; i < length; i++)
    {
        remainder = fs % 256;
        *(buffer + 7 - i) = remainder;
        fs = fs >> 8;
    }

}

// Given file descriptor and pointer to the some buffer of length 32
// For no salt, use zeroed out salt with saltlen = 1
void sha256(uint8_t* salt, int saltlen, FILE* fp, unsigned long long int fs, uint8_t* buffer)
{
    uint8_t fileContent[64] = {0};
    //Initial hash
    uint32_t hvec[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    uint32_t k[64] = {0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};

    //Word buffer
    uint32_t w[64] = {0};

    int read_bytes = fread(fileContent,1,64,fp);
    //Adding salt
    for(int i = 0; i < saltlen; i++)
    {
        fileContent[i] = fileContent[i] ^ salt[i];
    }

    int bitLength = 0;
    uint32_t s0,s1;
    uint32_t a,b,c,d,e,f,g,h,S0,S1,ch,temp1,temp2,maj;
    //After reading some byte from file, perform hashing.
    while(read_bytes == 64)
    {
        //Appending 0x10000000 to the byte afterwards.
        //fileContent[read_bytes] = 128;
        //bitLength = 8 * read_bytes;
        //fileContent[62] = bitLength / 256;
        //fileContent[63] = bitLength % 256;

        //Copying from 8bit array to 32bit
        for(int i = 0; i < 16; i++)
        {
            w[i] = (fileContent[4*i] << 24) + (fileContent[4 * i + 1] << 16) + (fileContent[4 * i + 2] << 8) + fileContent[4*i + 3];
        }

        for(int i = 16; i < 64; i++)
        {
            s0 = rotr(w[i-15],7) ^ rotr(w[i-15], 18) ^ (w[i-15] >> 3);
            s1 = rotr(w[i-2],17) ^ rotr(w[i-2], 19) ^ (w[i-2] >> 10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }

        a = hvec[0];
        b = hvec[1];
        c = hvec[2];
        d = hvec[3];
        e = hvec[4];
        f = hvec[5];
        g = hvec[6];
        h = hvec[7];
        for(int i = 0; i < 64; i++)
        {
            S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
            ch = (e & f) ^ ((~e) & g);
            temp1 = (h + S1 + ch + k[i] + w[i]); //% (4294967296);
            S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
            maj = (a & b) ^ (a & c) ^ (b & c);
            temp2 = (S0 + maj);// % 4294967296;
            h = g;
            g = f;
            f = e;
            e = (d + temp1);// % 4294967296;
            d = c;
            c = b;
            b = a;
            a = (temp1 + temp2);// % 4294967296;
        }

        hvec[0] += a;
        hvec[1] += b;
        hvec[2] += c;
        hvec[3] += d;
        hvec[4] += e;
        hvec[5] += f;
        hvec[6] += g;
        hvec[7] += h;

        memset(fileContent,0,64);
        memset(w,0,64);
        read_bytes = fread(fileContent,1,64,fp);
    }

    //Last file-induced block
    //If less than 56 bytes read, this is the final "block".
    if(read_bytes < 56)
    {
        fileContent[read_bytes] = 0b10000000;
        //56~63: Appending filesize
        nFilesize_bytes(fs,fileContent + 56);
        

        //Copying from 8bit array to 32bit
        for(int i = 0; i < 16; i++)
        {
            w[i] = (fileContent[4*i] << 24) + (fileContent[4 * i + 1] << 16) + (fileContent[4 * i + 2] << 8) + fileContent[4*i + 3];
        }

        for(int i = 16; i < 64; i++)
        {
            s0 = rotr(w[i-15],7) ^ rotr(w[i-15], 18) ^ (w[i-15] >> 3);
            s1 = rotr(w[i-2],17) ^ rotr(w[i-2], 19) ^ (w[i-2] >> 10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }

        a = hvec[0];
        b = hvec[1];
        c = hvec[2];
        d = hvec[3];
        e = hvec[4];
        f = hvec[5];
        g = hvec[6];
        h = hvec[7];
        for(int i = 0; i < 64; i++)
        {
            S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
            ch = (e & f) ^ ((~e) & g);
            temp1 = (h + S1 + ch + k[i] + w[i]); //% (4294967296);
            S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
            maj = (a & b) ^ (a & c) ^ (b & c);
            temp2 = (S0 + maj);// % 4294967296;
            h = g;
            g = f;
            f = e;
            e = (d + temp1);// % 4294967296;
            d = c;
            c = b;
            b = a;
            a = (temp1 + temp2);// % 4294967296;
        }

        hvec[0] += a;
        hvec[1] += b;
        hvec[2] += c;
        hvec[3] += d;
        hvec[4] += e;
        hvec[5] += f;
        hvec[6] += g;
        hvec[7] += h;
    }
    else            //Otherwise another block is needed.
    {
        fileContent[read_bytes] = 0b10000000;

        for(int i = 0; i < 16; i++)
        {
            w[i] = (fileContent[4*i] << 24) + (fileContent[4 * i + 1] << 16) + (fileContent[4 * i + 2] << 8) + fileContent[4*i + 3];
        }

        for(int i = 16; i < 64; i++)
        {
            s0 = rotr(w[i-15],7) ^ rotr(w[i-15], 18) ^ (w[i-15] >> 3);
            s1 = rotr(w[i-2],17) ^ rotr(w[i-2], 19) ^ (w[i-2] >> 10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }

        a = hvec[0];
        b = hvec[1];
        c = hvec[2];
        d = hvec[3];
        e = hvec[4];
        f = hvec[5];
        g = hvec[6];
        h = hvec[7];
        for(int i = 0; i < 64; i++)
        {
            S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
            ch = (e & f) ^ ((~e) & g);
            temp1 = (h + S1 + ch + k[i] + w[i]); //% (4294967296);
            S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
            maj = (a & b) ^ (a & c) ^ (b & c);
            temp2 = (S0 + maj);// % 4294967296;
            h = g;
            g = f;
            f = e;
            e = (d + temp1);// % 4294967296;
            d = c;
            c = b;
            b = a;
            a = (temp1 + temp2);// % 4294967296;
        }

        hvec[0] += a;
        hvec[1] += b;
        hvec[2] += c;
        hvec[3] += d;
        hvec[4] += e;
        hvec[5] += f;
        hvec[6] += g;
        hvec[7] += h;


        memset(fileContent,0,64);
        memset(w,0,64);

        //The FINAL block.
        nFilesize_bytes(fs,fileContent + 56);

        for(int i = 0; i < 16; i++)
        {
            w[i] = (fileContent[4*i] << 24) + (fileContent[4 * i + 1] << 16) + (fileContent[4 * i + 2] << 8) + fileContent[4*i + 3];
        }

        for(int i = 16; i < 64; i++)
        {
            s0 = rotr(w[i-15],7) ^ rotr(w[i-15], 18) ^ (w[i-15] >> 3);
            s1 = rotr(w[i-2],17) ^ rotr(w[i-2], 19) ^ (w[i-2] >> 10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }

        a = hvec[0];
        b = hvec[1];
        c = hvec[2];
        d = hvec[3];
        e = hvec[4];
        f = hvec[5];
        g = hvec[6];
        h = hvec[7];
        for(int i = 0; i < 64; i++)
        {
            S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
            ch = (e & f) ^ ((~e) & g);
            temp1 = (h + S1 + ch + k[i] + w[i]); //% (4294967296);
            S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
            maj = (a & b) ^ (a & c) ^ (b & c);
            temp2 = (S0 + maj);// % 4294967296;
            h = g;
            g = f;
            f = e;
            e = (d + temp1);// % 4294967296;
            d = c;
            c = b;
            b = a;
            a = (temp1 + temp2);// % 4294967296;
        }

        hvec[0] += a;
        hvec[1] += b;
        hvec[2] += c;
        hvec[3] += d;
        hvec[4] += e;
        hvec[5] += f;
        hvec[6] += g;
        hvec[7] += h;
    }


    for(int i = 0; i < 8; i++)
    {
        buffer[4 * i] = (hvec[i] >> 24);
        buffer[4 * i + 1] = (hvec[i] << 8) >> 24;
        buffer[4 * i + 2] = (hvec[i] << 16) >> 24;
        buffer[4 * i + 3] = (hvec[i] << 24) >> 24;
    }

    rewind(fp);
}