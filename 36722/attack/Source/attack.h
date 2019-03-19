#ifndef __ATTACK_H
#define __ATTACK_H

#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <string.h>

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

#define AES_ENC_RND_ROW_STEP(a, b, c, d, e, f, g, h) \
    {                                                \
        aes_gf28_t __a1 = s[a];                      \
        aes_gf28_t __b1 = s[b];                      \
        aes_gf28_t __c1 = s[c];                      \
        aes_gf28_t __d1 = s[d];                      \
        s[e] = __a1;                                 \
        s[f] = __b1;                                 \
        s[g] = __c1;                                 \
        s[h] = __d1;                                 \
    }

#define AES_ENC_RND_MIX_STEP(a, b, c, d)       \
    {                                          \
        aes_gf28_t __a1 = s[a];                \
        aes_gf28_t __b1 = s[b];                \
        aes_gf28_t __c1 = s[c];                \
        aes_gf28_t __d1 = s[d];                \
                                               \
        aes_gf28_t __a2 = aes_gf28_mulx(__a1); \
        aes_gf28_t __b2 = aes_gf28_mulx(__b1); \
        aes_gf28_t __c2 = aes_gf28_mulx(__c1); \
        aes_gf28_t __d2 = aes_gf28_mulx(__d1); \
                                               \
        aes_gf28_t __a3 = __a1 ^ __a2;         \
        aes_gf28_t __b3 = __b1 ^ __b2;         \
        aes_gf28_t __c3 = __c1 ^ __c2;         \
        aes_gf28_t __d3 = __d1 ^ __d2;         \
                                               \
        s[a] = __a2 ^ __b3 ^ __c1 ^ __d1;      \
        s[b] = __a1 ^ __b2 ^ __c3 ^ __d1;      \
        s[c] = __a1 ^ __b1 ^ __c2 ^ __d3;      \
        s[d] = __a3 ^ __b1 ^ __c1 ^ __d2;      \
    }

void read_text_block(uint32_t x, uint8_t block[x][16]);
void print_text_block(uint32_t x, uint8_t block[x][16], uint32_t index);
void read_trace_block(int16_t *block);
char itoh(uint8_t n);
void compute_sbox_table();
void octetstr_wr(FILE *dest, const uint8_t *x, int n_x);
void aes_enc(uint8_t *r, const uint8_t *m, const uint8_t *k);
#endif