#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <assert.h>
#include <math.h>

#include <sys/random.h>
#include <unistd.h>
#include <getopt.h>
#include <signal.h>

#include "parameters.h"
#include "api.h"
#include "parsing.h"
#include "hqc.h"
#include "gf2x.h"
#include "code.h"
#include "vector.h"
#include "../lib/fips202/fips202.h"
#include <immintrin.h>
#include <x86intrin.h>
#include "shake_prng.h"
#include "shake_ds.h"

#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/bn.h>
#include "exploit_util/isa.c"
#include "exploit_util/util.c"
#include "exploit_util_local/crypto_util.c"

#define N 1000000

int main(int argc, char **argv) {
  unsigned char pk[PUBLIC_KEY_BYTES];
  unsigned char sk[SECRET_KEY_BYTES];
  unsigned char ct[CIPHERTEXT_BYTES];
  unsigned char key1[SHARED_SECRET_BYTES];
  unsigned char key2[SHARED_SECRET_BYTES];

  uint8_t entropy_input[48];
  for (size_t i = 0; i < 48; ++i) {
    entropy_input[i] = i;
  }
  shake_prng_init(entropy_input, NULL, 48, 0);

  if (argc < 2) {
    puts("Usage: ./program <outputfile>");
    exit(1);
  }

  const char *outputfile = argv[1];

  crypto_kem_keypair(pk, sk);

  printf("Writing timings to %s\n", outputfile);
  FILE *timings = fopen(outputfile, "w");
  if (timings == NULL) {
    perror("Could not open timings file");
    exit(1);
  }

  printf("Starting timings...\n");
  fprintf(timings, "sexp,outer,inner,time\n");

  for (size_t j = 0; j < N; ++j) {
    crypto_kem_enc(ct, key1, pk);
    bzero(key2, SHARED_SECRET_BYTES);

    uint64_t a = tic();
    crypto_kem_dec(key2, ct, sk);
    uint64_t b = toc();

    check_key(key1, key2, SHARED_SECRET_BYTES);

    uint64_t m[VEC_K_SIZE_64] = {0};
    crypto_kem_dec_m(m, ct, sk);
    struct timing_info ti = message_timing(m);
    if (fprintf(timings, "%zu,%zu,%zu,%zu\n", ti.seed_expander_iters, ti.outer_iters, ti.inner_iters, b - a) < 0) {
        perror("Failed to write timings");
        exit(1);
    }
  }

  fclose(timings);
}
