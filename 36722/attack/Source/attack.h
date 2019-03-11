#ifndef __ATTACK_H
#define __ATTACK_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define TRACEPATH "traces.dat"
#define HEXSTRING "0123456789ABCDEF"

#define READ_INT(n)                \
    {                              \
        n = getc(traces);          \
        n |= (getc(traces) << 8);  \
        n |= (getc(traces) << 16); \
        n |= (getc(traces) << 24); \
        printf(#n" : %u\n", n);    \
    }

#define FREE_ALLOCATED \
    {                  \
        free(m);       \
        free(c);       \
        free(T);       \
    }

int hamming_weight(unsigned int n);
void read_text_block(uint8_t *block);
void print_text_block(uint8_t *block, uint32_t index);
void read_trace_block(int16_t *block);

#endif