#include "attack.h"

FILE *traces;
uint32_t t, s, h = 256;

#define ANTSEC_S ((int) (s / 4))
#define ANTSEC_T (100)

uint8_t actual_key[16] = {0xCD, 0x97, 0x16, 0xE9, 0x5B, 0x42, 0xDD, 0x48,
                          0x69, 0x77, 0x2A, 0x34, 0x6A, 0x7F, 0x58, 0x13};


//s / 4 100
// 50 at 0.702321 (MAX)
// 114 at 0.629247
// 205 at 0.626534

//s / 2 200
// 205 0.60278 (MAX)

//s / 3 100
// 205 0.626534 (MAX)

//s / 3.5 100
// 205 0.626534 (MAX)

//s / 3.75 100
// 205 0.626534 (MAX)

//s / 3.9 100
// 205 0.626534 (MAX)

int main(int argc, char *argv[]) {
    traces = fopen(TRACEPATH, "r");
    if (traces == NULL) {
        printf("<traces.dat> not found, exiting.\n");
        return 0;
    }

    READ_INT(t);
    READ_INT(s);

    uint8_t m[t][16];
    read_text_block(t, m);

    uint8_t c[t][16];
    read_text_block(t, c);

    printf("Reading traces...\n");
    int16_t *T = malloc(sizeof(uint16_t) * s * t);  //[s][t]
    read_trace_block(T);

    printf("Calculating key hypotheses...\n");
    double H[h][ANTSEC_T];
    for (int j = 0; j < ANTSEC_T; ++j) {
        for (int i = 0; i < h; ++i) {
            H[i][j] = (double)hamming_weight(m[j][0] ^ i);
        }
    }

    printf("Casting traces to doubles...\n");
    double *doubled_T = malloc(sizeof(double) * ANTSEC_S * ANTSEC_T);
    for (int _s = 0; _s < ANTSEC_S; ++_s) {
        for (int _t = 0; _t < ANTSEC_T; ++_t) {
            doubled_T[ANTSEC_T * _s + _t] = (double)T[t * _s + _t];
        }
    }
    // double ehis[h], ehi2s[h];
    // printf("Calculating ehi and ehi2...\n");
    // for (int i = 0; i < h; ++i) {
    //     ehis[i] = kahan_summing(H[i], ANTSEC_T);
    //     ehi2s[i] = kahan_square_summing(H[i],ANTSEC_T);
    // }
    // double eTis[ANTSEC_S], eTi2s[ANTSEC_S];
    // printf("Calculating eTi and eTi2...\n");
    // for (int i = 0; i < ANTSEC_S; ++i) {
    //     eTis[i] = kahan_summing(&doubled_T[ANTSEC_T * i], ANTSEC_T);
    //     eTi2s[i] = kahan_square_summing(&doubled_T[ANTSEC_T * i], ANTSEC_T);
    // }
    // printf("Calculating ehiTis...\n");
    // double *ehiTis = malloc(sizeof(double) * ANTSEC_S * h);
    // for (int _h = 0; _h < h; ++_h) {
    //     printf("ehitis iteration %d\n", _h);
    //     for (int _s = 0; _s < ANTSEC_S; ++_s) {
    //         ehiTis[ANTSEC_S * _h + _s] =
    //             kahan_multiply_summing(H[_h], &doubled_T[_s * ANTSEC_T],
    //             ANTSEC_T);
    //     }
    // }
    printf("Calculating pearson correlation coefficients...\n");
    double *results = malloc(sizeof(double) * ANTSEC_S * h);
    for (int _h = 0; _h < h; ++_h) {
        printf("pcc iteration %d\n", _h);
        for (int _s = 0; _s < ANTSEC_S; ++_s) {
            // double cov = ANTSEC_T * ehiTis[ANTSEC_S * _h + _s] - ehis[_h] *
            // eTis[_s]; double sd_H = sqrt(ANTSEC_T * ehi2s[_h] -
            // ehis[_h]*ehis[_h]); double sd_T = sqrt(ANTSEC_T * eTi2s[_s] -
            // eTis[_s]*eTis[_s]);
            results[_h * ANTSEC_S + _s] =
                gsl_stats_correlation(H[_h], 1, &doubled_T[ANTSEC_T * _s], 1,
                                      ANTSEC_T);  // cov / (sd_H * sd_T);// //
        }
    }

    double max_val = 0.0f;
    int max = -1;
    for (int _h = 0; _h < h; ++_h) {
        for (int _s = 0; _s < ANTSEC_S; ++_s) {
            // if (_h < 255) {
            //     if (results[_h * ANTSEC_S + _s] <
            //         results[(_h + 1) * ANTSEC_S + _s]) {
            //         _h += 1;
            //     }
            // }
            if (max_val < results[_h * ANTSEC_S + _s] && (_h > 200)) {
                max_val = results[_h * ANTSEC_S + _s];
                max = _h;
            }
        }
    }
    printf("MAX INDEX is %d, ", max);
printf("MAX VALUE is %f, ", max_val);
    printf("Finished...\n");

    free(T);
    return 0;
}

double kahan_summing(double *data, size_t size) {
    long double mean = 0;
    for (int i = 0; i < size; ++i) {
        mean += (data[i] - mean) / (i + 1);
    }
    return (double)mean;
}
double kahan_square_summing(double *data, size_t size) {
    long double mean = 0;
    for (int i = 0; i < size; ++i) {
        mean += ((data[i] * data[i]) - mean) / (i + 1);
    }
    return (double)mean;
}
double kahan_multiply_summing(double *data1, double *data2, size_t size) {
    long double mean = 0;
    for (int i = 0; i < size; ++i) {
        mean += ((data1[i] * data2[i]) - mean) / (i + 1);
    }
    return (double)mean;
}

double optimised_pearson(double exi, double eyi, double exi2, double eyi2,
                         double exiyi, size_t size) {
    double cov = size * exiyi - exi * eyi;
    double sd_x = sqrt(size * exi2 - exi * exi);
    double sd_y = sqrt(size * eyi2 - eyi * eyi);
    return (cov / (sd_x * sd_y));
}

// float mean(int16_t *data, int length) {
//     float mean = 0.0f;
//     for (int i = 0; i < length; ++i) mean += data[i];
//     return (mean / length);
// }

// float co_variance(int16_t *data_x, int16_t *data_y, float mean_x, float
// mean_y,
//                   int length) {
//     float cov = 0.0f;
//     for (int i = 0; i < length; ++i)
//         cov += (((float)data_x[i] - mean_x) * ((float)data_y[i] - mean_y));
//     return (cov / length);
// }

// float standard_deviation(int16_t *data, float mean, int length) {
//     float sd = 0.0f;
//     // for (int i = 0; i < length; ++i) sum += data[i];
//     // mean = sum / length;
//     for (int i = 0; i < length; ++i) sd += pow((float)data[i] - mean, 2);
//     return sqrt(sd / length);
// }

// float pearson_coco(int16_t *data_x, int16_t *data_y, int length) {
//     float mean_x = mean(data_x, length);
//     float mean_y = mean(data_y, length);
//     float sd_x = standard_deviation(data_x, mean_x, length);
//     float sd_y = standard_deviation(data_y, mean_y, length);
//     float cov = co_variance(data_x, data_y, mean_x, mean_y, length);
//     float pcc = ((cov) / (sd_x * sd_y));
//     return pcc;
// }

void aes_enc_rnd_key(uint8_t *s, const uint8_t *rk) {
    for (int i = 0; i < 16; ++i) s[i] = s[i] ^ rk[i];
}

uint8_t hamming_weight(uint8_t n) { return __builtin_popcount(n); }

char itoh(uint8_t n) {
    if (n < 16) return HEXSTRING[n];
    return 'Z';
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