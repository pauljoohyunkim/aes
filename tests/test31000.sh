#!/bin/bash
head -c 16007 /dev/urandom > testfile
head -c 32 /dev/urandom > testkey


./aes_enc -i testfile -k testkey -u 1 -t 3 -s 
./aes_dec -i testfile.aes -k testkey -u 1 
original=$(sha256sum testfile | cut -d" " -f1)
tested=$(sha256sum testfile.aes.decrypted | cut -d" " -f1)
rm testfile testfile.aes testfile.aes.decrypted testkey
if [ "$original" == "$tested" ]; then
	exit 0
else
	exit 1
fi