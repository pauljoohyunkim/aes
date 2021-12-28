#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <time.h>


#include "aes_common.h"
#include "ctr_common.h"
#include "file_common.h"
#include "../hash/sha2.h"

/*
From aes_common.h header

uint8_t buffer[16] = {0};       //For data
uint8_t key[32] = {0};          //For key
uint8_t expanded_key[480];      //Size will be (keylen) * (number of round keys). https://en.wikipedia.org/wiki/AES_key_schedule
int nRoundKeys;                 //For key scheduling
int nWords;                     //For key scheduling
int nRounds;                    //Number of rounds: 10 for AES128, 12 for AES192, 14 for AES256
int keylen = 0;                 //Length of key (16 for AES128, 24 for AES192, 32 for AES256) 

*/

/*
From ctr_common.h header

uint8_t iv[16] = { 0 };             //iv is the initialization vector.
uint8_t counter[16] = { 0 };        //counter counts so that it can produce the ctr_vec
uint8_t ctr_vec[16] = { 0 };        //ctr_vec = iv ^ counter
*/

void* aes_process(void* ptr);



char* inputfilename;
char* outputfilename;
uint8_t aesFileHeader[3] = {0};     //First byte represents AES type. Second byte represents password-check skip flag.
                                    //Third byte represents file-integrity-check skip flag.
uint8_t aesFileHeaderRaw[3] = {0};  //The header read straight from the file.
unsigned long long int inputfilesize = 0;       //Size of the input file in bytes


char default_extension[] = ".decrypted";

//File descriptors
FILE* inputfile;
FILE* keyfile;
FILE* outputfile;
FILE* plainfile;

uint8_t salted_pass_hash[32] = {0};
uint8_t computed_pass_hash[32] = {0};
uint8_t integrity_hash[32] = {0};
uint8_t computed_integrity_hash[32] = {0};

//Option Flags
bool optT = false, optI = false, optK = false, optO = false, optS = false, optF = false, optU = false, optQ = false;

//
bool integritycheck = false;

//Job done flag
bool done = false;

#if __has_include(<pthread.h>)
unsigned long long int processedbytes = 0;
long updateFrequency = 5;
#endif

// For status update while processing. (<pthread.h>-existing environment exclusive feature)
#if __has_include(<pthread.h>)
#include <pthread.h>

void* status(void *ptr)
{
    while(done == false)
    {
        printf("[INFO] %llu/%llu bytes processed.\n",processedbytes,inputfilesize);
        sleep(updateFrequency);
    }
}
#endif

//Displaying help
void help()
{
    char helptext[] = 
        "\n"
        "Usage: aes_dec -i <encrypted file> -k <key file> [other options]\n"
        "\n"
        " Required options:\n"
        "\n"
        "       -i <encrypted file>: name of the file you wish to decrypt\n"
        "       -k <key file>: file containing your key.\n"
        "\n"
        " Common options:\n"
        "\n"
        "       -o <output file>: specify the output file. (default: <input file>.decrypted)\n"
        "       (Warning: Do not set the output file to be equal to the input file.)\n"
        #if __has_include(<pthread.h>)
        "       -u <positive integer>: status update frequency. (default: 5)\n"
        "       -q: disable status update during encryption.\n"
        #endif
        "\n"
        " Override options:\n"
        "       -t <AES type>: overrides AES bit mode detection to the specified mode (1:128bit, 2:192bit, 3:256bit)\n"
        "       -s: disable password check when decrypting.\n"
        "       -f: disable file integrity check after decrypting.\n";
    printf("%s",helptext);
}


int main(int argc, char** argv)
{
    //Initialization
    //round const
    for(int i = 0; i < 10; i++)
    {
        rcon[i][0] = rc[i];
    }

    //IV generation is not needed anymore.

    // Files
    
    int read_bytes;         //Bytes of file read.
    

    // Option handling.
    int opt;
    #if __has_include(<pthread.h>)
    while((opt = getopt(argc, argv, ":t:i:k:o:u:hsfq")) != -1)
    #else
    while((opt = getopt(argc, argv, ":t:i:k:o:hsf")) != -1)
    #endif
    {
        switch (opt)
        {
        //AES TYPE
        case 't':
            optT = true;
            switch (optarg[0])
            {
                case '1':
                    printf("AES Type (Forced): AES-128\n");
                    *aesFileHeader = 1;
                    nRoundKeys = 11;
                    nWords = 4;
                    nRounds = 10;
                    break;
                case '2':
                    printf("AES Type (Forced): AES-192\n");
                    *aesFileHeader = 2;
                    nRoundKeys = 13;
                    nWords = 6;
                    nRounds = 12;
                    break;
                case '3':
                    printf("AES Type (Forced): AES-256\n");
                    *aesFileHeader = 3;
                    nRoundKeys = 15;
                    nWords = 8;
                    nRounds = 14;
                    break;
                default:
                    printf("[ERROR] Unknown AES Type. 1 for AES-128, 2 for AES-192, and 3 for AES-256\n");
                    return 1;
            }
            keylen = 4 * nWords;
            break;
        //INPUT FILE
        case 'i':
            optI = true;
            inputfile = fopen(optarg,"rb");
            if(inputfile == NULL)
            {
                printf("[ERROR] Encrypted file could not be opened.\n");
                fclose(inputfile);
                return 1;
            }
            else
            {
                printf("Encrypted File: %s\n", optarg);
                //Copying encrypted file name to the memory.
                inputfilename = (char*) malloc((strlen(optarg) + 10) * sizeof(char));
                strcpy(inputfilename,optarg);
                inputfilesize = filesize(inputfile);
                printf("Encrypted file \"%s\": %llu bytes\n", inputfilename, inputfilesize);
                break;
            }
            break;
        //KEY FILE
        case 'k':
            optK = true;
            keyfile = fopen(optarg,"rb");
            if(keyfile == NULL)
            {
                printf("[ERROR] Key file could not be opened.\n");
                fclose(keyfile);
                return 1;
            }
            else
            {
                printf("Key File: %s\n", optarg);
                read_bytes = fread(key, 1, 32, keyfile);
                rewind(keyfile);
                break;
            }
            break;
        //OUTPUT FILE
        case 'o':
            optO = true;
            outputfile = fopen(optarg,"wb");
            //Copying output file name to the memory.
            outputfilename = (char*) malloc((strlen(optarg) + 10) * sizeof(char));
            strcpy(outputfilename,optarg);
            break;
        //HELP MENU
        case 'h':
            help();
            return 0;
        //"Secure-ish"... This can be used to prevent brute forcing.
        case 's':
            optS = true;
            *(aesFileHeader + 1) = 1;
            break;
        //File-integrity check skip. If you want to save a few seconds...
        case 'f':
            optF = true;
            *(aesFileHeader + 2) = 1;
            break;
        
        #if __has_include(<pthread.h>)
        case 'u':
            optU = true;
            char* updateptr;
            updateFrequency = strtol(optarg,&updateptr,10);
            if (*updateptr)
            {
                printf("[ERROR] Unrecognized part: \"%s\"\n", updateptr);
                return 1;
            }
            if (updateFrequency <= 0)
            {
                printf("[ERROR] Update frequency cannot be negative. Please input a positive integer.\n");
                return 1;
            }
            printf("[INFO] Status update every %ld seconds.\n",updateFrequency);
            break;
        case 'q':
            optQ = true;
            printf("[INFO] Status update during AES encryption disabled.\n");
            break;
        #endif

        case ':':
            printf("[ERROR] Option argument not specified.\n");
            return 1;
        case '?':
            printf("[ERROR] Unknown option \"%c\" specified. Try option \"h\" for help.\n", optopt);
            return 1;
        }
    }
    //Required options ("i", "k") check
    if(!(optK && optI))
    {
        printf("At least one of the required options (\"i\", \"k\") not provided.\n");
        return 1;
    }
    //Check if output file is set or not. If not, default filename.
    if(!optO)
    {
        outputfilename = (char*) malloc((strlen(inputfilename) + 15) * sizeof(char));
        strcpy(outputfilename,inputfilename);
        strcat(outputfilename,default_extension);
        outputfile = fopen(outputfilename,"wb");
    }
    //Reading header
    if(fread(aesFileHeaderRaw,1,3,inputfile) != 3)
    {
        printf("[ERROR] The file header cannot be read. Terminating.\n");
        return 1;
    }
    //Reading IV
    if(fread(iv,1,16,inputfile) != 16)
    {
        printf("[ERROR] The IV cannot be read. Terminating. \n");
        return 1;
    }
    for(int i = 0; i < 16; i++)
    {
        ctr_vec[i] = iv[i];
    }

    /* Header Processing
    Need to check for each option from the raw header.
    */


    //Type detection (A)
    if(!optT)
    {
        if(aesFileHeaderRaw[0] == 1)
        {
            aesFileHeader[0] = 1;
            printf("AES Type Detection: AES-128\n");
            nRoundKeys = 11;
            nWords = 4;
            nRounds = 10;
            keylen = 4 * nWords;
        }
        else if(aesFileHeaderRaw[0] == 2)
        {
            aesFileHeader[0] = 2;
            printf("AES Type Detection: AES-192\n");
            nRoundKeys = 13;
            nWords = 6;
            nRounds = 12;
            keylen = 4 * nWords;
        }
        else if(aesFileHeaderRaw[0] == 3)
        {
            aesFileHeader[0] = 3;
            printf("AES Type Detection: AES-256\n");
            nRoundKeys = 15;
            nWords = 8;
            nRounds = 14;
            keylen = 4 * nWords;
        }
        else
        {
            printf("[ERROR] AES type detection failed.\n");
            return 1;
        }
    }

    //Password hash (P)
    //Password hash included.
    if(aesFileHeaderRaw[1] == 0)
    {
        //Skip password check
        if(optS)
        {
            //Throwing away the included password hash
            fread(salted_pass_hash,1,16,inputfile);
        }
        //Do password check
        else
        {
            aesFileHeader[1] = 0;
            sha256(ctr_vec,16,keyfile,keylen,computed_pass_hash);
            fread(salted_pass_hash,1,32,inputfile);
            for(int i = 0; i < 32; i++)
            {
                if(salted_pass_hash[i] != computed_pass_hash[i])
                {
                    printf("[ERROR] Wrong password file. Terminating.\n");
                    return 1;
                }
            }
            
            printf("[INFO] Password accepted.\n");
            
        }
    }
    //Password not included
    else
    {
        printf("[INFO] Password hash is not included during encryption, so password check is disabled.\n");
    }

    //read_bytes = fread(key, 1, 32, keyfile);
    //Key file will be closed after salting and hashing.

    //File integrity check
    //File integrity header included
    if(aesFileHeaderRaw[2] == 0)
    {
        //Skip file integrity check
        if(optF)
        {
            //Throwing away the included integrity check hash
            fread(integrity_hash,1,32,inputfile);
        }
        else
        {
            aesFileHeaderRaw[2] = 0;
            fread(integrity_hash,1,32,inputfile);
            integritycheck = true;
            printf("[INFO] File integrity check scheduled.\n");
        }
    }
    //File integrity hash not included
    else
    {
        printf("[INFO] File integrity hash is not included during encryption, so file integrity check is disabled.\n");
    }

    //Check key length
    if(read_bytes > keylen)
    {
        printf("[WARNING] The AES type requires %d bytes as the key, the only the first %d bytes of the key file is read.\n", keylen, keylen);
    }
    else if (read_bytes == 0)
    {
        printf("[ERROR] Zero byte read from the key file. Check your key file again. Terminating...\n");
        return 1;
    }
    else if (read_bytes > 0 && read_bytes < keylen)
    {
        printf("[INFO] Since the selected AES type requires %d bytes as the key, and the provided key file supplied %d bytes, %d bytes are padded with zeros.\n", keylen, read_bytes, keylen - read_bytes);
    }


    //Closing key file.
    fclose(keyfile);

    //Threads for status update.
    #if __has_include(<pthread.h>)
    if(optQ)
    {
        int* t;
        aes_process((void*) t);
    }
    else
    {
        pthread_t status_thread, aes_thread;
        int* t1,t2;
        pthread_create(&status_thread, NULL, status, (void*) t1);
        pthread_create(&aes_thread, NULL, aes_process, (void*) t2);
        pthread_join(status_thread, NULL);
        pthread_join(aes_thread, NULL);
    }
    //If pthread.h is not supported, just use a normal function call without thread support.
    #else
    int* t;
    aes_process((void*) t);
    #endif



    fclose(inputfile);
    fclose(outputfile);

    printf("\n[INFO] Decryption complete! Saved as: %s\n", outputfilename);

    //File integrity check
    if(integritycheck)
    {
        printf("[INFO] Integrity check starting...\n");
        plainfile = fopen(outputfilename,"rb");
        unsigned long long int plainfilesize = filesize(plainfile);
        sha256(key,keylen,plainfile,plainfilesize,computed_integrity_hash);
        for(int i = 0; i < 32; i++)
        {
            if(computed_integrity_hash[i] != integrity_hash[i])
            {
                printf("[ERROR] Mismatching integrity hash.\n");
                return 1;
            }
        }
        
        printf("[INFO] Integrity hash verified.\n");
        
        fclose(plainfile);
    }

    free(inputfilename);
    free(outputfilename);

    return 0;
}


void* aes_process(void* ptr)
{
    //After reading 16 bytes...
    int read_bytes = fread(buffer, 1, 16,inputfile);
    while(read_bytes == 16)
    {
        aes(ctr_vec);           //AES on ctr_vec

        //XOR-ing with the buffer
        for(int i = 0; i < 16; i++)
        {
            buffer[i] = buffer[i] ^ ctr_vec[i];
        }

        //Write 16 bytes
        fwrite(buffer, 1, 16,outputfile);

        #if __has_include(<pthread.h>)
        processedbytes += 16;
        #endif
        
        counter_inc();
        for(int index = 0; index < 16; index++)
        {
            ctr_vec[index] = iv[index] ^ counter[index];
        }
        read_bytes = fread(buffer, 1, 16,inputfile);
    }

    //Potential last block
    if(read_bytes != 0)
    {
        aes(ctr_vec);

        //XOR-ing with the buffer
        for(int i = 0; i < 16; i++)
        {
            buffer[i] = buffer[i] ^ ctr_vec[i];
        }

        //Write the number of bytes required
        fwrite(buffer, 1, read_bytes,outputfile);

        #if __has_include(<pthread.h>)
        processedbytes += read_bytes;
        #endif
    }

    // Job done flag = true
    done = true;

}