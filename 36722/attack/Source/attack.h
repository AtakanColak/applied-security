#ifndef __ATTACK_H
#define __ATTACK_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>

#define HEXSTRING "0123456789ABCDEF"

#define READ_INT(n)                \
    {                              \
        n = getc(traces);          \
        n |= (getc(traces) << 8);  \
        n |= (getc(traces) << 16); \
        n |= (getc(traces) << 24); \
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
void octetstr_wr(const uint8_t *x, int n_x);
#endif