/* Copyright (C) 2019 Atakan Colak 
 *
 * Use of this source code is restricted per the CC BY-NC-ND license, a copy of 
 * which can be found via http://creativecommons.org (and should be included as 
 * LICENSE.txt within the associated archive or repository).
 */

#ifndef __ATARSA_H
#define __ATARSA_H

#include  <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <time.h>

#include <gmp.h>

#define ATARSA_BIT_LENGTH 1024
#define PRINT 1
// #define MAX(x, y) ({x > y ? x : y;})
// #define MIN(x, y) ({x > y ? y : x;})

void print_str(const char * str);
void print_mpz(mpz_t n);
void atarsa_primegen(mpz_t p, int lambda);
void rsa_keygen( mpz_t N, mpz_t e, mpz_t d, int lambda);

#endif
