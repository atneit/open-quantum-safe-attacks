#ifndef HQC_H
#define HQC_H

/**
 * @file hqc.h
 * @brief Functions of the HQC_PKE IND_CPA scheme
 */

#include <stdint.h>
#include <immintrin.h>
#include "api.h"

void hqc_pke_keygen(unsigned char* pk, unsigned char* sk);
void hqc_pke_encrypt(uint64_t *u, uint64_t *v, uint64_t *m, unsigned char *theta, const unsigned char *pk);
void hqc_pke_decrypt(uint64_t *m, const __m256i *u_256, const uint64_t *v, const uint8_t *sk);
void hqc_pke_decrypt_sk(uint64_t *m, const __m256i *u_256, const uint64_t *v, const __m256i *y_256);
void hqc_pke_encrypt_timings(struct timings* t, uint64_t *u, uint64_t *v, uint64_t *m, unsigned char *theta, const unsigned char *pk);

#endif