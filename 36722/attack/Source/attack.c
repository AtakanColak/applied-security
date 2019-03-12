#include "attack.h"

FILE *traces;
uint32_t t, s;

uint8_t actual_key[16] = {0xCD, 0x97, 0x16, 0xE9, 0x5B, 0x42, 0xDD, 0x48,
                          0x69, 0x77, 0x2A, 0x34, 0x6A, 0x7F, 0x58, 0x13};

int main(int argc, char *argv[]) {
    traces = fopen(TRACEPATH, "r");
    if (traces == NULL) {
        printf("<traces.dat> not found, exiting.");
        return 0;
    }

    READ_INT(t);
    READ_INT(s);

    uint8_t *m = malloc(sizeof(uint8_t) * 16 * t);
    read_text_block(m);
    uint8_t *c = malloc(sizeof(uint8_t) * 16 * t);
    read_text_block(c);
    int16_t *T = malloc(sizeof(int16_t) * s * t);
    read_trace_block(T);

    float sd_H[HCOUNT], sd_T[s];
    float mean_H[HCOUNT], mean_T[s];
    int16_t H[HCOUNT][t]; 
    for (int j = 0; j < t; ++j) {
        for (int i = 0; i < HCOUNT; ++i) {
            H[j][i] = hamming_weight(m[j * 16] ^ i);
        }
    }

    // float *results = malloc(sizeof(float) * s * 256);
    // int16_t hypos[t], reals[t];
    // float mean_H[256], mean_T[s];
    // float sd_H[256], sd_T[s];
    // for(int i = 0; i < t; ++i) {
    //     printf("H[i * 256 + 2] = %d\n", H[i * 256 + 2]);
    //     hypos[i] = H[i * 256 + 2];
    // }
    // printf("Mean is %f\n", mean(hypos, t));
    // printf("Standard Dev is %f\n", standard_deviation(hypos, mean(hypos, t), t));
    // CALC MEAN AND STANDARD DEV FOR HYPOS
    // for (int j = 0; j < 256; ++j) {
    //     printf("HYPO MEAN AND SD ITERATION %d\n ", j);
    //     for (int i = 0; i < t; ++i) {
    //         hypos[i] = H[i * 256 + j];
    //     }
    //     mean_H[j] = mean(hypos, t);
    //     sd_H[j] = standard_deviation(hypos, mean_H[j], t);
    // }
    // // CALC MEAN AND STANDARD DEV FOR REALS
    // for (int j = 0; j < s; ++j) {
    //     // printf("REAL MEAN AND SD ITERATION %d\n ", j);
    //     for (int i = 0; i < t; ++i) {
    //         reals[i] = T[i * s + j];
    //     }
    //     mean_T[j] = mean(reals, t);
    //     sd_T[j] = standard_deviation(reals, mean_T[j], t);
    // }

    // // CALC PEARSON_COEFFICIENTS
    // for (int j = 0; j < 256; ++j) {
    //     printf("PCC ITERATION %d\n ", j);
    //     for (int i = 0; i < t; ++i) {
    //         hypos[i] = H[i * 256 + j];
    //     }
    //     for (int i = 0; i < s; ++i) {
    //         for (int k = 0; k < t; ++k) {
    //             reals[k] = T[k * s + i];
    //         }
    //         float cov = co_variance(hypos, reals, mean_H[j], mean_T[i], t);
    //         results[j * s + i] = ((cov) / (sd_H[j] * sd_T[i]));
    //     }
    // }

    // int best_index = -1;
    // float max = 0.0f;
    // for (int i = 0; i < 256; ++i) {
    //     for (int j = 0; j < s; ++j) {
    //         if (results[i * s + j] > max) {
    //             max = results[i * s + j];
    //             best_index = i;
    //         }
    //     }
    // }

    // printf("MAX CORRELATION IS %f\n", max);
    // printf("Key is %c%c\n", itoh((uint8_t)best_index >> 4),
    //        itoh((uint8_t)best_index & 0x0F));
    // print_text_block(m, 1);
    // print_text_block(c, 1);
    // print_text_block(m, 2);
    // print_text_block(c, 2);
    FREE_ALLOCATED;
    return 0;
}

float mean(int16_t *data, int length) {
    float mean = 0.0f;
    for (int i = 0; i < length; ++i) mean += data[i];
    return (mean / length);
}

float co_variance(int16_t *data_x, int16_t *data_y, float mean_x, float mean_y,
                  int length) {
    float cov = 0.0f;
    for (int i = 0; i < length; ++i)
        cov += (((float)data_x[i] - mean_x) * ((float)data_y[i] - mean_y));
    return (cov / length);
}

float standard_deviation(int16_t *data, float mean, int length) {
    float sd = 0.0f;
    // for (int i = 0; i < length; ++i) sum += data[i];
    // mean = sum / length;
    for (int i = 0; i < length; ++i) sd += pow((float)data[i] - mean, 2);
    return sqrt(sd / length);
}

float pearson_coco(int16_t *data_x, int16_t *data_y, int length) {
    float mean_x = mean(data_x, length);
    float mean_y = mean(data_y, length);
    float sd_x = standard_deviation(data_x, mean_x, length);
    float sd_y = standard_deviation(data_y, mean_y, length);
    float cov = co_variance(data_x, data_y, mean_x, mean_y, length);
    float pcc = ((cov) / (sd_x * sd_y));
    return pcc;
}

void aes_enc_rnd_key(uint8_t *s, const uint8_t *rk) {
    for (int i = 0; i < 16; ++i) s[i] = s[i] ^ rk[i];
}

uint8_t hamming_weight(uint8_t n) { return __builtin_popcount(n); }

char itoh(uint8_t n) {
    if (n < 16) return HEXSTRING[n];
    return 'Z';
}

void read_text_block(uint8_t *block) {
    for (int i = 0; i < t; ++i)
        for (int j = 0; j < 16; ++j) block[i * 16 + j] = getc(traces);
}

void print_text_block(uint8_t *block, uint32_t index) {
    printf("\n");
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            uint8_t n = block[16 * index + 4 * i + j];
            printf("%c%c\t", itoh(n >> 4), itoh(n & 0x0F));
        }
        printf("\n");
    }
}

void read_trace_block(int16_t *block) {
    for (int i = 0; i < t; ++i) {
        for (int j = 0; j < s; ++j) {
            block[i * s + j] = getc(traces);
            block[i * s + j] |= (getc(traces) << 8);
        }
    }
}