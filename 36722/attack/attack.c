#include "attack.h"

FILE *traces;
uint32_t t, s;

#define READ_INT(n)               \
    {                             \
        n = getc(traces);         \
        n |= (getc(traces) << 8); \
        n |= (getc(traces) << 8); \
        n |= (getc(traces) << 8); \
    }

#define FREE_ALLOCATED \
    {                  \
        free(m);       \
        free(c);       \
        free(T);       \
    }




char *hex_string = "0123456789ABCDEF";

char itoh(uint8_t n)
{
    if (n < 16)
        return hex_string[n];
    return 'Z';
}

void read_text_block(uint8_t * block)
{
    for (int i = 0; i < t; ++i)
        for (int j = 0; j < 16; ++j)
            block[i * 16 + j] = getc(traces);
}

void print_text_block(uint8_t * block, uint32_t index)
{
    printf("\n");
    for (int i = 0; i < 4; ++i)
    {
        for (int j = 0; j < 4; ++j)
        {
            uint8_t n = block[16 * index + 4 * i + j];
            printf("%c%c\t", itoh(n >> 4), itoh(n & 0x0F));
        }
        printf("\n");
    }
}

void read_trace_block(int16_t * block) {
    for(int i = 0; i < t; ++i){
        for(int j = 0; j < s; ++j) {
            block[i*s + j] = getc(traces);
            block[i*s + j] |= (getc(traces) << 8);
        }
    }
}

int main(int argc, char *argv[])
{
    traces = fopen("traces.dat", "r");
    if (traces == NULL)
    {
        printf("<traces.dat> not found, exiting.");
        return 0;
    }

    READ_INT(t);
    printf("t is %u\n", t);
    READ_INT(s);
    printf("s is %u\n", s);

    uint8_t *m = malloc(sizeof(uint8_t) * 16 * t);
    read_text_block(m);
    uint8_t *c = malloc(sizeof(uint8_t) * 16 * t);
    read_text_block(c);
    int16_t *T = malloc(sizeof(int16_t) * s * t);
    read_trace_block(T);


    unsigned int i = 0;
    while(EOF != getc(traces)) 
    {
        i++;
    }
    printf("%u\n",i);
    // uint8_t eol = getc(traces);
    // if(eol != NULL)
    //     printf("0x%c%c\n", itoh(eol >> 4), itoh(eol & 0x0F));
    // print_text_block(m, 1);
    // print_text_block(c, 1);
    // print_text_block(m, 2);
    // print_text_block(c, 2);
    FREE_ALLOCATED;
    return 0;
}