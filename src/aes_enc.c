#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <time.h>



#include "aes_common.h"
#include "ctr_common.h"

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
char* inputfilename;
char* outputfilename;


char default_extension[] = ".aes";

//Option Flags
bool optT = false, optI = false, optK = false, optO = false, optS = false;

//Displaying help
void help()
{
    char helptext[] = 
        "\n"
        "Usage: aes_enc -t <AES type> -i <input file> -k <key file> [other options]\n"
        "\n"
        " Required options:\n"
        "\n"
        "       -t <AES type>: AES bit mode (1:128bit, 2:192bit, 3:256bit)\n"
        "       -i <input file>: name of the file you wish to encrypt\n"
        "       -k <key file>: file containing your key.\n"
        "\n"
        " Common options:\n"
        "\n"
        "       -o <output file>: specify the output file. (default: <input file>.aes)\n"
        "       (Warning: Do not set the output file to be equal to the input file.)\n"
        "       -s: disable password check when decrypting.\n";
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
    //IV generation
    srand(time(NULL));
    iv_gen()



    // Files
    FILE* inputfile;
    FILE* keyfile;
    int read_bytes;         //Bytes of keyfile read.
    FILE* outputfile;

    // Option handling.
    int opt;
    while((opt = getopt(argc, argv, ":t:i:k:o:hs")) != -1)
    {
        switch (opt)
        {
        //AES TYPE
        case 't':
            optT = true;
            switch (optarg[0])
            {
                case '1':
                    printf("AES Type: AES-128\n");
                    nRoundKeys = 11;
                    nWords = 4;
                    nRounds = 10;
                    break;
                case '2':
                    printf("AES Type: AES-192\n");
                    nRoundKeys = 13;
                    nWords = 6;
                    nRounds = 12;
                    break;
                case '3':
                    printf("AES Type: AES-256\n");
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
            inputfile = fopen(optarg,"r");
            if(inputfile == NULL)
            {
                printf("[ERROR] Input file could not be opened.\n");
                fclose(inputfile);
                return 1;
            }
            else
            {
                printf("Input File: %s\n", optarg);
                //Copying input file name to the memory.
                inputfilename = (char*) malloc((strlen(optarg) + 10) * sizeof(char));
                strcpy(inputfilename,optarg);
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
                fclose(keyfile);
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
        //"Secure-ish"... This prevents brute forcing.
        case 's':
            optS = true;
            break;
        case ':':
            printf("[ERROR] Option argument not specified.\n");
            return 1;
        case '?':
            printf("[ERROR] Unknown option \"%c\" specified. Try option \"h\" for help.\n", optopt);
            return 1;
        }
    }
    //Required options ("t", "i", "k") check
    if(!((optT && optI) && optK))
    {
        printf("At least one of the required options (\"t\", \"i\", \"k\") not provided.\n");
        return 1;
    }
    //Check if output file is set or not. If not, default filename.
    if(!optO)
    {
        outputfilename = (char*) malloc((strlen(inputfilename) + 10) * sizeof(char));
        strcpy(outputfilename,inputfilename);
        strcat(outputfilename,default_extension);
        outputfile = fopen(outputfilename,"wb");
    }
    //Check key length
    if(read_bytes > keylen)
    {
        printf("[WARNING] Since the selected AES type requires %d bytes as the key, the only the first %d bytes of the key file is read.\n", keylen, keylen);
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
    
    free(inputfilename);
    free(outputfilename);


    fread(buffer,1, 16,inputfile);

    












    fclose(inputfile);
    fclose(outputfile);


    return 0;
}