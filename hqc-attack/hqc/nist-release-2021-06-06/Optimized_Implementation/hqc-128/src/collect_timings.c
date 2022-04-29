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

#define N 100
#define ITERS 100000

int main(int argc, char **argv) {
  unsigned char pk[PUBLIC_KEY_BYTES];
  unsigned char sk[SECRET_KEY_BYTES];
  unsigned char ct[N][CIPHERTEXT_BYTES];
  unsigned char key1[N][SHARED_SECRET_BYTES];
  unsigned char key2[SHARED_SECRET_BYTES];

  if (argc < 2) {
    puts("Usage: ./program <outputfile>");
    exit(1);
  }

  const char *outputfile = argv[1];

  crypto_kem_keypair(pk, sk);
  for (int i = 0; i < N; ++i) {
    bzero(key2, SHARED_SECRET_BYTES);
    crypto_kem_enc(ct[i], key1[i], pk);
    crypto_kem_dec(key2, ct[i], sk);
    check_key(key1[i], key2, SHARED_SECRET_BYTES);
  }

  uint8_t entropy_input[48];
  for (size_t i = 0; i < 48; ++i) {
    entropy_input[i] = i;
  }
  shake_prng_init(entropy_input, NULL, 48, 0);

  printf("Writing timings to %s\n", outputfile);
  FILE *timings = fopen(outputfile, "w");
  if (timings == NULL) {
    perror("Could not open timings file");
    exit(1);
  }

  printf("Starting timings...\n");
  fprintf(timings, "key,iter,sub,time\n");

  size_t order[N];
  for (size_t j = 0; j < N; ++j) {
    order[j] = j;
  }

  for (int i = 0; i < ITERS; ++i) {
    shuffle(order, N);
    for (int j = 0; j < N; ++j) {
      size_t iN = order[j];

      struct timings t = crypto_kem_dec_timings(key2, ct[iN], sk);

      check_key(key1[iN], key2, SHARED_SECRET_BYTES);

      if (fprintf(timings, "%zu,%d,all,%lu\n", iN, i, t.t[SUB_TIMINGS-1] - t.t[0]) < 0) {
        perror("Failed to write timings");
        exit(1);
      }
      uint64_t last_timestamp = t.t[0];
      for (size_t k = 1; k < SUB_TIMINGS; ++k) {
        uint64_t elapsed = t.t[k] - last_timestamp;
        last_timestamp = t.t[k];
        if (fprintf(timings, "%zu,%d,%lu,%lu\n", iN, i, k, elapsed) < 0) {
          perror("Failed to write timings");
          exit(1);
        }
      }
    }
  }

  fclose(timings);
}
