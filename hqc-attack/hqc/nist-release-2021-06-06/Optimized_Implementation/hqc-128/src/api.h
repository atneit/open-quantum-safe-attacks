/**
 * @file api.h
 * @brief NIST KEM API used by the HQC_KEM IND-CCA2 scheme
 */

#ifndef API_H
#define API_H

#include <x86intrin.h>
#include <stdint.h>
#define CRYPTO_ALGNAME                      "HQC-128"

#define CRYPTO_SECRETKEYBYTES               2289
#define CRYPTO_PUBLICKEYBYTES               2249
#define CRYPTO_BYTES                        64
#define CRYPTO_CIPHERTEXTBYTES              4481

// As a technicality, the public key is appended to the secret key in order to respect the NIST API.
// Without this constraint, CRYPTO_SECRETKEYBYTES would be defined as 32

int crypto_kem_keypair(unsigned char* pk, unsigned char* sk);
int crypto_kem_enc(unsigned char* ct, unsigned char* ss, const unsigned char* pk);
int crypto_kem_dec(unsigned char* ss, const unsigned char* ct, const unsigned char* sk);

void crypto_kem_dec_m(uint64_t *m /* VEC_K_SIZE_64 */, const unsigned char *ct, const unsigned char *sk);
int crypto_kem_dec_sk(unsigned char *ss, const unsigned char *ct, const uint8_t* pk, const __m256i *y_256);

struct timing_info {
  uint64_t outer_iters;
  uint64_t inner_iters;
  uint64_t seed_expander_iters;
};

#define SUB_TIMINGS 8
struct timings {
    int rv;
    struct timing_info ti;
    uint64_t t[SUB_TIMINGS];
};

struct timings crypto_kem_dec_timings(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);

#endif
