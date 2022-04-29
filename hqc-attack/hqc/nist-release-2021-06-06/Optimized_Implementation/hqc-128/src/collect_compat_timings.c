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
#include <immintrin.h>
#include <x86intrin.h>

#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/bn.h>
#include "exploit_util/isa.c"
#include "exploit_util/util.c"

#define ITERS 10000000

int main(int argc, char **argv) {
  unsigned char pk[PUBLIC_KEY_BYTES];
  unsigned char sk[SECRET_KEY_BYTES];
  unsigned char ct[CIPHERTEXT_BYTES];
  unsigned char key1[SHARED_SECRET_BYTES];
  unsigned char key2[SHARED_SECRET_BYTES];

  if (argc < 2) {
    puts("Usage: ./program <outputfile>");
    exit(1);
  }

  const char *outputfile = argv[1];

  crypto_kem_keypair(pk, sk);

  uint8_t entropy_input[48];
  for (size_t i = 0; i < 48; ++i) {
    entropy_input[i] = i;
  }
  shake_prng_init(entropy_input, NULL, 48, 0);

  printf("Writing compat timings to %s\n", outputfile);
  FILE *timings_compat = fopen(outputfile, "w");
  if (timings_compat == NULL) {
    perror("Could not open compat timings file");
    exit(1);
  }

  printf("Starting timings...\n");
  fprintf(timings_compat, "key,Algorithm,Num. Seedexpansions,Num. PRNG Samplings $\\theta$,Clock cycles\n");

  for (int i = 0; i < ITERS; ++i) {
    crypto_kem_enc(ct, key1, pk);
    struct timings t = crypto_kem_dec_timings(key2, ct, sk);

    check_key(key1, key2, SHARED_SECRET_BYTES);

    if (fprintf(timings_compat, "%d,HQC-128,%lu,%lu,%lu\n", i, t.ti.seed_expander_iters, t.ti.inner_iters, t.t[SUB_TIMINGS-1] - t.t[0]) < 0) {
      perror("Failed to write timings");
      exit(1);
    }
  }

  fclose(timings_compat);
}
