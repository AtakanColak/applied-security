#include "attack.h"

typedef uint8_t aes_gf28_t;
aes_gf28_t AES_RC[10] = {0x01, 0x02, 0x04, 0x08, 0x10,
                         0x20, 0x40, 0x80, 0x1B, 0x36};

FILE *traces;
uint32_t t, s, h = 256;
uint8_t sbox[256];
// (s / 27) IS MINIMUM WORKING VALUE FOR ANTSEC_S
#define ANTSEC_S ((s / 27))
// 150 IS MINIMUM WORKING VALUE FOR ANTSEC_T
#define ANTSEC_T (150)
// uint8_t actual_key[16] = {0xCD, 0x97, 0x16, 0xE9, 0x5B, 0x42, 0xDD, 0x48,
//   0x69, 0x77, 0x2A, 0x34, 0x6A, 0x7F, 0x58, 0x13};

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(
            stderr,
            "Incorrect Usage. Please use the program as ./attack ${FILE}\n");
        return 0;
    }

    traces = fopen(argv[1], "r");
    if (traces == NULL) {
        fprintf(stderr, "File %s not found.\n", argv[1]);
        return 0;
    }

    // int mtc = 225;
    // srand(time(NULL));
    // uint8_t nr[mtc][16];
    // for(int i = 0; i < mtc; ++i)
    //     for(int j = 0; j < 16; ++j)
    //         nr[i][j] = rand();

    // int pid = fork();
    // if (pid == 0) {
    //     sleep(3);
    //     //MAKE CONNECTION
    //     //START SENDING ALL MESSAGES
    //     return 0;
    // }

    compute_sbox_table();
    READ_INT(t);
    READ_INT(s);

    uint8_t m[t][16];
    read_text_block(t, m);

    uint8_t c[t][16];
    read_text_block(t, c);

    uint8_t k[16];

    // printf("Reading traces...\n");
    int16_t *T = malloc(sizeof(uint16_t) * s * t);
    read_trace_block(T);

    time_t seconds = time(NULL);
    short *used_T = malloc(sizeof(short) * ANTSEC_S * ANTSEC_T);
    long eTis[ANTSEC_S], eT2is[ANTSEC_S];
    float sd_T[ANTSEC_S];
    for (int _s = 0; _s < ANTSEC_S; ++_s) {
        for (int _t = 0; _t < ANTSEC_T; ++_t) {
            used_T[ANTSEC_T * _s + _t] = T[t * _s + _t];
        }
        sums_and_standard_deviation(&sd_T[_s], &eTis[_s], &eT2is[_s],
                                    &used_T[ANTSEC_T * _s], ANTSEC_T);
    }
    for (int b = 0; b < 16; ++b) {
        short * H = malloc (sizeof(short) * h * ANTSEC_T);
        for (int j = 0; j < ANTSEC_T; ++j) {
            for (int i = 0; i < h; ++i) {
                H[i * ANTSEC_T + j] = __builtin_popcount(sbox[m[j][b] ^ i]);
            }
        }

        float *results = malloc(sizeof(float) * ANTSEC_S * h);

        for (int _h = 0; _h < h; ++_h) {
            long ehi, ehi2i;
            long ehiTi[ANTSEC_S];
            memset(&ehiTi, 0, sizeof(long) * ANTSEC_S);
            for (int _t = 0; _t < ANTSEC_T; ++_t)
                for (int _s = 0; _s < ANTSEC_S; ++_s)
                    ehiTi[_s] += H[_h * ANTSEC_T + _t] * used_T[ANTSEC_T * _s + _t];
            float sd_H;
            sums_and_standard_deviation(&sd_H, &ehi, &ehi2i, &H[_h * ANTSEC_T], ANTSEC_T);
            for (int _s = 0; _s < ANTSEC_S; ++_s) {
                double cov = ANTSEC_T * ehiTi[_s] - ehi * eTis[_s];
                results[_h * ANTSEC_S + _s] = fabs(cov / (sd_H * sd_T[_s]));
            }
        }

        k[b] = get_row_of_max(results, h, ANTSEC_S);
        free(results);
        free(H);
    }
    fprintf(stdout, "Time taken \t = %lds\n", time(NULL) - seconds);
    fprintf(stdout, "Number of Traces = %d\n", ANTSEC_T);
    fprintf(stdout, "Key\t\t = ");
    octetstr_wr(stdout, k, 16);
    check_key(m[0], k, c[0]);
    free(used_T);
    free(T);
    return 0;
}

void sums_and_standard_deviation(float *sd_address, long *sum_address,
                                 long *sum2_address, short *row, int row_size) {
    *sum_address = 0;
    *sum2_address = 0;
    for (int _t = 0; _t < row_size; ++_t) {
        // used_T[ANTSEC_T * _s + _t] = T[t * _s + _t];
        long y = (long)row[_t];
        *sum_address += y;
        *sum2_address += y * y;
    }
    *sd_address = sqrt(ANTSEC_T * *sum2_address - *sum_address * *sum_address);
}

void check_key(uint8_t *m, uint8_t *k, uint8_t *c) {
    uint8_t cipher[16];
    aes_enc(cipher, m, k);
    int ctr = 0;
    for (int b = 0; b < 16; ++b)
        if (c[b] == cipher[b]) ctr++;
    if (ctr == 16)
        fprintf(stdout,
                "\nDPA attack on AES-128 is successful.\nM[0] generates C[0] "
                "with recovered key.\n\n");
    else
        fprintf(
            stderr,
            "DPA attack on AES-128 failed.\nNumber of keys that match is %d.\n",
            ctr);
}

int get_row_of_max(float *array, int row, int col) {
    int max_row = -1;
    float max_val = 0.0f;
    for (int r = 0; r < row; ++r)
        for (int c = 0; c < col; ++c)
            if (max_val < array[col * r + c]) {
                max_val = array[col * r + c];
                max_row = r;
            }

    return max_row;
}

char itoh(uint8_t n) {
    if (n < 16) return HEXSTRING[n];
    return 'Z';
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

void read_text_block(uint32_t x, uint8_t block[x][16]) {
    for (int i = 0; i < x; ++i)
        for (int j = 0; j < 16; ++j) {
            // printf("(i, j) = (%d,%d)\n", i, j);
            block[i][j] = getc(traces);
        }
}

void print_text_block(uint32_t x, uint8_t block[x][16], uint32_t index) {
    printf("\n");
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            uint8_t n = block[index][4 * i + j];
            printf("%c%c\t", itoh(n >> 4), itoh(n & 0x0F));
        }
        printf("\n");
    }
}

void read_trace_block(int16_t *block) {
    //[s][t] but getc goes on like s s first
    for (int i = 0; i < t; ++i) {
        for (int j = 0; j < s; ++j) {
            block[j * t + i] = getc(traces);
            block[j * t + i] |= (getc(traces) << 8);
        }
    }
}

uint8_t aes_gf28_mulx(uint8_t a) {
    if (a & 0x80)
        return 0x1B ^ (a << 1);
    else
        return (a << 1);
}

// Works
uint8_t aes_gf28_mul(uint8_t a, uint8_t b) {
    uint8_t t = 0;
    for (int i = 7; i >= 0; i--) {
        t = aes_gf28_mulx(t);
        if ((b >> i) & 1) t ^= a;
    }
    return t;
}
uint8_t aes_gf28_inv(uint8_t a) {
    // Fermats little theorem states that a ^ -1 is a ^ (q-2)
    uint8_t t_0 = aes_gf28_mul(a, a);    // a^2
    uint8_t t_1 = aes_gf28_mul(t_0, a);  // a^3
    t_0 = aes_gf28_mul(t_0, t_0);        // a^4
    t_1 = aes_gf28_mul(t_1, t_0);        // a^7
    t_0 = aes_gf28_mul(t_0, t_0);        // a^8
    t_0 = aes_gf28_mul(t_1, t_0);        // a^15
    t_0 = aes_gf28_mul(t_0, t_0);        // a^30
    t_0 = aes_gf28_mul(t_0, t_0);        // a^60
    t_1 = aes_gf28_mul(t_1, t_0);        // a^67
    t_0 = aes_gf28_mul(t_1, t_0);        // a^127
    t_0 = aes_gf28_mul(t_0, t_0);        // a^254
    return t_0;
}

uint8_t aes_enc_sbox(uint8_t a) {
    a = aes_gf28_inv(a);

    a = (0x63) ^ (a) ^ (a << 1) ^ (a >> 7) ^ (a << 2) ^ (a >> 6) ^ (a << 3) ^
        (a >> 5) ^ (a << 4) ^ (a >> 4);  // Left Bitwise Circular Shift
    // because left bitwise shift isn't cool enough
    return a;
}

void sub_word(aes_gf28_t *src) {
    for (int i = 0; i < 4; ++i) src[i] = aes_enc_sbox(src[i]);
}

void rot_word(aes_gf28_t *src) {
    aes_gf28_t temp = src[0];
    for (int i = 0; i < 3; ++i) src[i] = src[i + 1];
    src[3] = temp;
}

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

void aes_enc_rnd_key(aes_gf28_t *s, const aes_gf28_t *rk) {
    for (int i = 0; i < 16; ++i) s[i] = s[i] ^ rk[i];
}

void aes_enc_rnd_sub(aes_gf28_t *s) {
    for (int i = 0; i < 16; ++i) s[i] = aes_enc_sbox(s[i]);
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

void aes_enc(uint8_t *r, const uint8_t *m, const uint8_t *k) {
    aes_gf28_t rk[16], s[16];

    // aes_gf28_t * rcp = AES_RC;
    aes_gf28_t *rkp = rk;

    memcpy(s, m, sizeof(aes_gf28_t) * 16);
    memcpy(rkp, k, sizeof(aes_gf28_t) * 16);

    // 1 initial round
    aes_enc_rnd_key(s, rkp);
    // NR - 1 iterated rounds
    for (int i = 1; i < 10; ++i) {
        aes_enc_rnd_sub(s);
        aes_enc_rnd_row(s);
        aes_enc_rnd_mix(s);
        aes_enc_exp_step(rkp, AES_RC[i - 1]);
        aes_enc_rnd_key(s, rkp);
    }
    // 1 final round
    aes_enc_rnd_sub(s);
    aes_enc_rnd_row(s);
    aes_enc_exp_step(rkp, AES_RC[9]);
    aes_enc_rnd_key(s, rkp);

    memcpy(r, s, sizeof(aes_gf28_t) * 16);
}

void compute_sbox_table() {
    for (int b = 0; b < 256; ++b) sbox[b] = aes_enc_sbox(b);
}