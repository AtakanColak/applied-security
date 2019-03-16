#include "attack.h"

FILE *traces;
uint32_t t, s, h = 256;
uint8_t sbox[256];
// (s / 27) IS MINIMUM WORKING VALUE FOR ANTSEC_S
#define ANTSEC_S ((s / 27))
// 150 IS MINIMUM WORKING VALUE FOR ANTSEC_T
#define ANTSEC_T (150)
uint8_t actual_key[16] = {0xCD, 0x97, 0x16, 0xE9, 0x5B, 0x42, 0xDD, 0x48,
                          0x69, 0x77, 0x2A, 0x34, 0x6A, 0x7F, 0x58, 0x13};

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
    compute_sbox_table();
    READ_INT(t);
    READ_INT(s);

    uint8_t m[t][16];
    read_text_block(t, m);

    uint8_t c[t][16];
    read_text_block(t, c);

    uint8_t k[1][16];

    // printf("Reading traces...\n");
    int16_t *T = malloc(sizeof(uint16_t) * s * t);
    read_trace_block(T);

    time_t seconds = time(NULL);
    // printf("Using %d traces and %d samples from starting point\n", ANTSEC_T,
    //    ANTSEC_S);
    // printf(
    // "Calculating sums, square sums and standard deviations of traces...\n");
    short *doubled_T = malloc(sizeof(short) * ANTSEC_S * ANTSEC_T);
    // printf("\n");
    long eTis[ANTSEC_S];
    long eT2is[ANTSEC_S];
    float sd_T[ANTSEC_S];
    for (int _s = 0; _s < ANTSEC_S; ++_s) {
        eTis[_s] = 0;
        eT2is[_s] = 0;
        for (int _t = 0; _t < ANTSEC_T; ++_t) {
            long y = (long)T[t * _s + _t];
            doubled_T[ANTSEC_T * _s + _t] = (short)y;
            eTis[_s] += y;
            eT2is[_s] += y * y;
        }
        sd_T[_s] = sqrt(ANTSEC_T * eT2is[_s] - eTis[_s] * eTis[_s]);
    }
    for (int b = 0; b < 16; ++b) {
        // printf("Calculating key[%d]:\n", b);
        short H[h][ANTSEC_T];
        for (int j = 0; j < ANTSEC_T; ++j) {
            for (int i = 0; i < h; ++i) {
                H[i][j] = __builtin_popcount(sbox[m[j][b] ^ i]);
            }
        }

        float *results = malloc(sizeof(float) * ANTSEC_S * h);

        for (int _h = 0; _h < h; ++_h) {
            long ehi = 0;
            long ehi2i = 0;
            long ehiTi[ANTSEC_S];
            for (int _s = 0; _s < ANTSEC_S; ++_s) ehiTi[_s] = 0;
            for (int _t = 0; _t < ANTSEC_T; ++_t) {
                ehi += H[_h][_t];
                ehi2i += H[_h][_t] * H[_h][_t];
                for (int _s = 0; _s < ANTSEC_S; ++_s) {
                    ehiTi[_s] += H[_h][_t] * doubled_T[ANTSEC_T * _s + _t];
                }
            }
            double sd_H = sqrt(ANTSEC_T * ehi2i - ehi * ehi);
            for (int _s = 0; _s < ANTSEC_S; ++_s) {
                double cov = ANTSEC_T * ehiTi[_s] - ehi * eTis[_s];
                results[_h * ANTSEC_S + _s] = fabs(cov / (sd_H * sd_T[_s]));
            }
        }

        float max_val = 0.0f;
        int max = -1;
        for (int _h = 0; _h < h; ++_h) {
            for (int _s = 0; _s < ANTSEC_S; ++_s) {
                if (max_val < results[_h * ANTSEC_S + _s]) {
                    max_val = results[_h * ANTSEC_S + _s];
                    max = _h;
                }
            }
        }
        k[0][b] = (uint8_t)max;
        // printf("K[%d] = %c%c\n", b, itoh(max >> 4), itoh(max & 0x0F));
        free(results);
    }
    fprintf(stdout,"Time taken \t = %lds\n", time(NULL) - seconds);
    fprintf(stdout,"Number of Traces = %d\n", ANTSEC_T);
    fprintf(stdout,"Key\t\t = ");
    octetstr_wr(k[0], 16);
    // print_text_block(1, k, 0);
    int ctr = 0;
    int equal = 1;
    for (int b = 0; b < 16; ++b) {
        if (k[0][b] != actual_key[b])
            equal = 0;
        else {
            ctr++;
        }
    }
    if (equal == 1) {
        // printf("\nDPA attack on AES-128 is successful.\n");
        // printf("Heckid bY Attacckan.\n\n");
    } else {
        fprintf(stderr, "DPA attack on AES-128 failed.\n");
        fprintf(stderr, "Number of keys that match is %d.\n", ctr);
    }
    
    // fprintf(stdout, "Finished in %ld seconds...\n", time(NULL) - seconds);

    free(doubled_T);
    free(T);
    return 0;
}

char itoh(uint8_t n) {
    if (n < 16) return HEXSTRING[n];
    return 'Z';
}

void octetstr_wr(const uint8_t *x, int n_x) {
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
    fprintf(stdout, "%s\n", s); 
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

void compute_sbox_table() {
    for (int b = 0; b < 256; ++b) sbox[b] = aes_enc_sbox(b);
}