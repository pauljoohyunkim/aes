unsigned long long int filesize(FILE* fp);

//This function returns filesize given its descriptor (in "rb" mode.)
unsigned long long int filesize(FILE* fp)
{
    unsigned long long int size;
    fseek(fp,0,SEEK_END);
    size = (unsigned long long int) (ftell(fp));
    rewind(fp);
    return size;
}