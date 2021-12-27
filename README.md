# aes
Based on the old aes128 project of mine (https://github.com/pauljoohyunkim/aes128). This will be written more cleanly, and support more formats of AES.

# This repository is currently under construction.
Encryptor is almost ready. Decryptor is still under construction.
Should you wish to try it out, compile it by "gcc aes_enc.c -o aes_enc -lpthread"

## Encrypted File Format

Suppose "inputfile" contains some bytes "$$$$$$$$$$$$$$$$" and its cipher text is some "????????????????". The generated encrypted file will follow the following format.

"APF[16d][32p][32f]????????????????"

where
* A represents the format of the AES used. ("\x01" for AES-128, "\x02" for AES-192, and "\x03" for AES-256)
* P represents the flag for not allowing password checks. ("\x01" for skipping password checks.)
* F represents the flag for not allowing file integrity check after decryption.
* [16d] represents the 16 byte IV (initialization vector).
* [32p] represents the 32 byte SHA256 hash of the password file with IV as salt. (This will be missing if P is set to 1.)
* [32f] represents the 32 byte SHA256 hash of the file with the password as salt. (This will be missing if F is set to 1.)
* Salting is done by XOR-ing the salt with the file in the first "salt-len" bytes.

## Build Instruction
To build on a Unix environment that supports <pthread.h>, simply run the following command

> mkdir build
>
> cd build
>
> ../configure
>
> make
>
> make install

To build on other systems, navigate to the src/aes directory, and build using

> gcc aes_enc.c -o aes_enc -pthread

If for some reason the compilation fails due to the -pthread option, try again with -lpthread flag instead.

## aes_enc Option (-h)
Usage: aes_enc -t <AES type> -i <input file> -k <key file> [other options]


> Required options:
>
>       -t <AES type>: AES bit mode (1:128bit, 2:192bit, 3:256bit)
>       -i <input file>: name of the file you wish to encrypt
>       -k <key file>: file containing your key.
>
> Common options:
>
>       -o <output file>: specify the output file. (default: <input file>.aes)
>       (Warning: Do not set the output file to be equal to the input file.)
>       -u <positive integer>: status update frequency. (default: 5)     [ORIGINALLY UNIX-BASED ENVIORNMENT EXCLUSIVE]
>	-q: disable status update during encryption.			 [ORIGINALLY UNIX-BASED ENVIRONMENT EXCLUSIVE]
>       -s: disable password check when decrypting.
>       -f: disable file integrity check after decrypting.

Note that you can use any file as a key file, whether it is a text file, image file, etc, as long as you keep it secret.

Example)
> aes_enc -t1 -i secret_file.txt -k super_secret_key

Encrypts using AES128-CTR the file "secret_file.txt" using "super_secret_key" file as key file.
