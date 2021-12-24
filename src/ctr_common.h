/*
    This header files contains some of the functions and variables
    that all of the CTR block mode needs.
*/

uint8_t iv[16] = { 0 };             //iv is the initialization vector.
uint8_t counter[16] = { 0 };        //counter counts so that it can produce the ctr_vec
uint8_t ctr_vec[16] = { 0 };        //ctr_vec = iv ^ counter

//Generating IV
void iv_gen()
{
    for(int i = 0; i < 16; i++)
    {
        iv[i] = rand() % 256;
        ctr_vec[i] = iv[i];
    }
}

void counter_inc()
{
    for(int index = 15; index >= 0; index--)
    {
        if(counter[index] != 255)
        {
            counter[index]++;
            break;
        }
        else
        {
            counter[index] = 0;
        }
    }
}