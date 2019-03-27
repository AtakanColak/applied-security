/* Copyright (C) 2018 Daniel Page <csdsp@bristol.ac.uk>
 *
 * Use of this source code is restricted per the CC BY-NC-ND license, a copy of
 * which can be found via http://creativecommons.org (and should be included as
 * LICENSE.txt within the associated archive or repository).
 */

#include "ataes.h"

typedef uint8_t aes_gf28_t;
typedef uint32_t aes_gf28_word;
typedef uint8_t gf28_k;

int ghost = 0;

uint8_t mask = 0;
uint8_t mi[4];
uint8_t mi_primes[4];

aes_gf28_t AES_RC[10] = {0x01, 0x02, 0x04, 0x08, 0x10,
                         0x20, 0x40, 0x80, 0x1B, 0x36};
aes_gf28_t sbox_table[256];
aes_gf28_t maskbox_table[256];
#define NB 4
#define NR 9

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

#define AES_ENC_RND_MIX_STEP_MASKS                \
    {                                             \
        mask = r[0];                              \
        mi[0] = r[1];                             \
        mi[1] = r[2];                             \
        mi[2] = r[3];                             \
        mi[3] = r[4];                             \
        aes_gf28_t __a1 = r[1];                   \
        aes_gf28_t __b1 = r[2];                   \
        aes_gf28_t __c1 = r[3];                   \
        aes_gf28_t __d1 = r[4];                   \
                                                  \
        aes_gf28_t __a2 = aes_gf28_mulx(__a1);    \
        aes_gf28_t __b2 = aes_gf28_mulx(__b1);    \
        aes_gf28_t __c2 = aes_gf28_mulx(__c1);    \
        aes_gf28_t __d2 = aes_gf28_mulx(__d1);    \
                                                  \
        aes_gf28_t __a3 = __a1 ^ __a2;            \
        aes_gf28_t __b3 = __b1 ^ __b2;            \
        aes_gf28_t __c3 = __c1 ^ __c2;            \
        aes_gf28_t __d3 = __d1 ^ __d2;            \
                                                  \
        mi_primes[0] = __a2 ^ __b3 ^ __c1 ^ __d1; \
        mi_primes[1] = __a1 ^ __b2 ^ __c3 ^ __d1; \
        mi_primes[2] = __a1 ^ __b1 ^ __c2 ^ __d3; \
        mi_primes[3] = __a3 ^ __b1 ^ __c1 ^ __d2; \
    }

char *hex_string = "0123456789ABCDEF";

uint8_t htoi(char c) {
    for (uint8_t i = 0; i < 16; ++i)
        if (hex_string[i] == c) return i;
    return 16;
}

char itoh(uint8_t n) {
    if (n < 16) return hex_string[n];
    return 'Z';
}

aes_gf28_t aes_gf28_mulx(aes_gf28_t a) {
    if (a & 0x80)
        return 0x1B ^ (a << 1);
    else
        return (a << 1);
}

// Works
aes_gf28_t aes_gf28_mul(aes_gf28_t a, aes_gf28_t b) {
    aes_gf28_t t = 0;
    for (int i = 7; i >= 0; i--) {
        t = aes_gf28_mulx(t);
        if ((b >> i) & 1) t ^= a;
    }
    return t;
}

// Works
aes_gf28_t aes_gf28_inv(aes_gf28_t a) {
    // Fermats little theorem states that a ^ -1 is a ^ (q-2)
    aes_gf28_t t_0 = aes_gf28_mul(a, a);    // a^2
    aes_gf28_t t_1 = aes_gf28_mul(t_0, a);  // a^3
    t_0 = aes_gf28_mul(t_0, t_0);           // a^4
    t_1 = aes_gf28_mul(t_1, t_0);           // a^7
    t_0 = aes_gf28_mul(t_0, t_0);           // a^8
    t_0 = aes_gf28_mul(t_1, t_0);           // a^15
    t_0 = aes_gf28_mul(t_0, t_0);           // a^30
    t_0 = aes_gf28_mul(t_0, t_0);           // a^60
    t_1 = aes_gf28_mul(t_1, t_0);           // a^67
    t_0 = aes_gf28_mul(t_1, t_0);           // a^127
    t_0 = aes_gf28_mul(t_0, t_0);           // a^254
    return t_0;
}

// Works
aes_gf28_t aes_enc_sbox(aes_gf28_t a) {
    a = aes_gf28_inv(a);

    a = (0x63) ^ (a) ^ (a << 1) ^ (a >> 7) ^ (a << 2) ^ (a >> 6) ^ (a << 3) ^
        (a >> 5) ^ (a << 4) ^ (a >> 4);  // Left Bitwise Circular Shift
    // because left bitwise shift isn't cool enough
    return a;
}

void compute_sbox_table() {
    for (int b = 0; b < 256; ++b) sbox_table[b] = aes_enc_sbox(b);
}
void compute_maskbox_table() {
    for (int b = 0; b < 256; ++b) {
        maskbox_table[b ^ mask] = sbox_table[b] ^ mask;
    }
}

// Works
void sub_word(aes_gf28_t *src) {
    for (int i = 0; i < 4; ++i) src[i] = sbox_table[src[i]];
}

// Works
void rot_word(aes_gf28_t *src) {
    aes_gf28_t temp = src[0];
    for (int i = 0; i < 3; ++i) src[i] = src[i + 1];
    src[3] = temp;
}

// Nk number of 32 bit word compromising Cipher Key

void aes_enc_exp_step(aes_gf28_t *rk, aes_gf28_t rc) {
    aes_gf28_t temp[4];

    int i = 0;
    while (i < 4) {
        for (int j = 0; j < 4; ++j) temp[j] = rk[4 * ((i + 3) % 4) + j];

        if (i == 0) {
            rot_word(temp);
            sub_word(temp);
            temp[0] ^= rc;
        }

        for (int j = 0; j < 4; ++j) rk[4 * i + j] ^= temp[j];

        i = i + 1;
    }
}

void aes_enc_rnd_key(aes_gf28_t *s, aes_gf28_t *rk) {
    for (int i = 0; i < 16; ++i) s[i] = s[i] ^ rk[i];
}

void aes_enc_rnd_key_init(aes_gf28_t *s, const aes_gf28_t *rk) {
    for (int i = 0; i < 16; ++i)
        s[i] = s[i] ^ rk[i];// ^ mask;  // ^ mi_primes[i % 4];
}

void aes_enc_rnd_sub(aes_gf28_t *s) {
    for (int i = 0; i < 16; ++i) s[i] = maskbox_table[s[i]];
}

void aes_enc_rnd_row(aes_gf28_t *s) {
    AES_ENC_RND_ROW_STEP(1, 5, 9, 13, 13, 1, 5, 9);
    AES_ENC_RND_ROW_STEP(2, 6, 10, 14, 10, 14, 2, 6);
    AES_ENC_RND_ROW_STEP(3, 7, 11, 15, 7, 11, 15, 3);
}

void aes_enc_rnd_mix(aes_gf28_t *s) {
    AES_ENC_RND_MIX_STEP(0, 1, 2, 3);
    AES_ENC_RND_MIX_STEP(4, 5, 6, 7);
    AES_ENC_RND_MIX_STEP(8, 9, 10, 11);
    AES_ENC_RND_MIX_STEP(12, 13, 14, 15);
}

void aes_init(const uint8_t *k, const uint8_t *r) { return; }

void initial_mask(uint8_t *s) {
    for (int i = 0; i < 16; ++i)
        s[i] = s[i] ^ mi_primes[i % 4];
}

void re_mask(uint8_t *s) {
    for (int i = 0; i < 16; ++i)
        s[i] = s[i] ^ mi[i % 4];
}

void apply_m(uint8_t *s) {
for (int i = 0; i < 16; ++i) s[i] = s[i] ^ mask;
}

void aes(uint8_t *c, const uint8_t *m, const uint8_t *k) {
    aes_gf28_t rk[16], s[16];

    // aes_gf28_t * rcp = AES_RC;
    aes_gf28_t *rkp = rk;

    memcpy(s, m, sizeof(aes_gf28_t) * 16);
    memcpy(rkp, k, sizeof(aes_gf28_t) * 16);

    // 1 initial round
    aes_enc_rnd_key(s, rkp);
    apply_m(s);
    // initial_mask(s);
    // NR - 1 iterated rounds
    for (int i = 1; i < 10; ++i) {
        aes_enc_rnd_sub(s);
        aes_enc_rnd_row(s);
        // re_mask(s);
        aes_enc_rnd_mix(s);
        aes_enc_exp_step(rkp, AES_RC[i - 1]);
        aes_enc_rnd_key(s, rkp);
    }
    // 1 final round
    aes_enc_rnd_sub(s);
    aes_enc_rnd_row(s);
    aes_enc_exp_step(rkp, AES_RC[9]);
    aes_enc_rnd_key(s, rkp);
    apply_m(s);
    memcpy(c, s, sizeof(aes_gf28_t) * 16);
    return;
}

void octetstr_wr(FILE *dest, const uint8_t *x, int n_x) {
    int len = 2 + 1 + 2 * (n_x) + 1;
    char s[len];
    s[0] = itoh(n_x >> 4);
    s[1] = itoh(n_x & 0x0F);
    s[2] = ':';

    for (int i = 0; i < n_x; ++i) {
        s[2 * i + 3] = itoh(x[i] >> 4);
        s[2 * i + 4] = itoh(x[i] & 0x0F);
    }
    s[2 * n_x + 3] = '\x00';
    fprintf(dest, "%s\n", s);
    // WRITE_BYTE('\x0D');
    return;
}

int main(int argc, char *argv[]) {
    // uint8_t k[16] = {0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
    //                  0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C};
    uint8_t k[16] = {0xCD, 0x97, 0x16, 0xE9, 0x5B, 0x42, 0xDD, 0x48,
                     0x69, 0x77, 0x2A, 0x34, 0x6A, 0x7F, 0x58, 0x13};
    // uint8_t m[16] = {0x32, 0x43, 0xF6, 0xA8, 0x88, 0x5A, 0x30, 0x8D,
    //                  0x31, 0x31, 0x98, 0xA2, 0xE0, 0x37, 0x07, 0x34};
    uint8_t m[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    // uint8_t c[16] = {0x39, 0x25, 0x84, 0x1D, 0x02, 0xDC, 0x09, 0xFB,
    //                  0xDC, 0x11, 0x85, 0x97, 0x19, 0x6A, 0x0B, 0x32};
    uint8_t t[16];

    uint8_t r[5] = {6, 0xDB, 0x13, 0x53, 0x45};
    AES_ENC_RND_MIX_STEP_MASKS;
    // fprintf(stdout, "R\t\t = ");
    // octetstr_wr(stdout, r, 5);
    // fprintf(stdout, "mask\t\t = ");
    // octetstr_wr(stdout, &mask, 1);
    // fprintf(stdout, "mi\t\t = ");
    // octetstr_wr(stdout, mi, 4);
    // fprintf(stdout, "mi_primes\t\t = ");
    // octetstr_wr(stdout, mi_primes, 4);
    compute_sbox_table();
    compute_maskbox_table();

    //  printf("\nTEST 7: ATAES\n");
    // printf("\nChecking if ataes_dec(ates_enc(m)) == m\n");
    aes(t, m, k);
    fprintf(stdout, "Ciphertext\t\t = ");
    octetstr_wr(stdout, t, 16);
    // AES_KEY rk;

    // AES_set_encrypt_key( k, 128, &rk );
    // AES_encrypt( m, t, &rk );

    // printf("\nTEST 1: mulx\n");
    // printf("%s * x == %s\n", itob(127), itob(aes_gf28_mulx(127)));
    // printf("%s * x == %s\n\n", itob(128), itob(aes_gf28_mulx(128)));

    // aes_gf28_t my_word[4]  = {0x09, 0xCF, 0xF4, 0x3C};
    // aes_gf28_t rotword[4] = {0xCF, 0xF4, 0x3C, 0x09};
    // aes_gf28_t subword[4] = {0x8A, 0x84, 0xEB, 0x01};

    // printf("\nTEST 2: rot_word\n");
    // rot_word(my_word);
    // printf("\nWhat rot_word does\n");
    // print_word(my_word);
    // printf("\nWhat rot_word should\n");
    // print_word(rotword);

    // printf("\nTEST 3: sub_word\n");
    // sub_word(my_word);
    // printf("\nWhat sub_word does\n");
    // print_word(my_word);
    // printf("\nWhat sub_word should\n");
    // print_word(subword);

    // printf("\nTEST 4: aes_enc_exp_step\n");
    // //for (int i = 1; i < 11; ++i)
    //   //aes_enc_exp_step(k, AES_RC[i-1]);
    // //printf("\nWhat aes_enc_exp_step is \n");
    // //print_block(k);
    // //printf("\nWhat aes_enc_exp_step should \n");
    // printf("\nPreviously tested, works. \n");
    // //print_block(finalkey);

    // printf("\nTEST 5: aes_dec_sbox\n");
    // for(int i = 0; i < 256; ++i) {
    //   uint8_t sbox = aes_enc_sbox(i);
    //   sbox = aes_dec_sbox(sbox);
    //   if (sbox != i) {
    //     printf("\n inv_sbox(sbox(%d)) == %d\nERROR RETURN\n", i, sbox);
    //     break;
    //   }
    // }
    // // printf("\naes_dec_sbox test end\n");

    // printf("\nTEST 6: aes_dec_rnd_row\n");
    // uint8_t new_k[16];
    // memcpy(new_k, k, sizeof(uint8_t) * 16);
    // aes_enc_rnd_row(new_k);
    // aes_dec_rnd_row(new_k);
    // cmp_blk(k, new_k);
    // memcpy(new_k, c, sizeof(uint8_t) * 16);
    // aes_enc_rnd_row(new_k);
    // aes_dec_rnd_row(new_k);
    // cmp_blk(c, new_k);

    // printf("\nTEST 6: aes_dec_rnd_mix\n");
    // memcpy(new_k, k, sizeof(uint8_t) * 16);
    // aes_enc_rnd_mix(new_k);
    // aes_dec_rnd_mix(new_k);
    // cmp_blk(k, new_k);
    // print_block(new_k);
    // print_block(k);
    // aes_enc(t, m, k);

    // if( !memcmp( t, c, 16 * sizeof( uint8_t ) ) ) {
    //   printf( "AES.Enc( k, m ) == c\n" );
    // }
    // else {
    //   printf( "AES.Enc( k, m ) != c\n" );
    // }

    // printf("\nWhat it is\n");
    // print_block(t);

    // printf("\nWhat it should be\n");
    // print_block(c);

    // print_block(t);
    // aes_dec(t, t, k);
    // print_block(m);
    // print_block(t);
    // cmp_blk(m, t);
}
