#ifndef __ATTACK_H
#define __ATTACK_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <gsl/gsl_statistics.h>
#include <time.h>

#define TRACEPATH "traces.dat"
// #define WRITEPATH "results.dat"
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

void read_text_block(uint32_t x, uint8_t block[x][16]);
void print_text_block(uint32_t x, uint8_t block[x][16], uint32_t index);
void read_trace_block(int16_t *block);
char itoh(uint8_t n); 
void compute_sbox_table();
#endif