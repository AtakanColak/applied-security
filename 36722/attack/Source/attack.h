#ifndef __ATTACK_H
#define __ATTACK_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <gsl/gsl_statistics.h>

#define TRACEPATH "traces.dat"
#define WRITEPATH "results.dat"
#define HEXSTRING "0123456789ABCDEF"
// #define h 256

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

void aes_enc_rnd_key(uint8_t *s, const uint8_t *rk);
void read_text_block(uint32_t x, uint8_t block[x][16]);
void print_text_block(uint32_t x, uint8_t block[x][16], uint32_t index);
void read_trace_block(int16_t *block);
char itoh(uint8_t n); 
double kahan_summing(double * data, size_t size);
double kahan_square_summing(double *data, size_t size);
double kahan_multiply_summing(double *data1, double *data2, size_t size);
uint8_t hamming_weight(uint8_t n);
float mean(int16_t* data, int length);
float co_variance(int16_t * data_x, int16_t * data_y, float mean_x, float mean_y, int length);
float standard_deviation(int16_t *data, float mean, int length); 
float pearson_coco(int16_t * data_x, int16_t * data_y, int length);
#endif