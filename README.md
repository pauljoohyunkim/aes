# aes
Based on the old aes128 project of mine (https://github.com/pauljoohyunkim/aes128). This will be written more cleanly, and support more formats of AES.

# This repository is currently under construction.
Encryptor is almost ready. Decryptor is still under construction.

## Encrypted file format

Suppose "inputfile" contains some bytes "$$$$$$$$$$$$$$$$" and its cipher text is some "????????????????". The generated encrypted file will follow the following format.

"APF[16d][32p][32f]????????????????"

where
* A represents the format of the AES used. ("\x01" for AES-128, "\x02" for AES-192, and "\x03" for AES-256)
* P represents the flag for not allowing password checks. ("\x01" for skipping password checks.)
* F represents the flag for not allowing
* [16d] represents the 16 byte IV (initialization vector).
* [32p] represents the 32 byte SHA256 hash of the password file with IV as salt. (This will be missing if P is set to 1.)
* [32f] represents the 32 byte SHA256 hash of the file with the password as salt.
* Salting is done by XOR-ing the salt with the file in the first "salt-len" bytes.