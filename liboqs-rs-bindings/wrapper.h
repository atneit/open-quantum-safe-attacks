// wrapper.h

#include "liboqs/build/include/oqs/oqs.h"

/* We also need the following internal definitions that are not part of the official api. */

/* FRODOKEM */

void oqs_kem_frodokem_640_shake_pack(unsigned char *out, const size_t outlen, const uint16_t *in, const size_t inlen, const unsigned char lsb);
void oqs_kem_frodokem_640_shake_unpack(uint16_t *out, const size_t outlen, const unsigned char *in, const size_t inlen, const unsigned char lsb);

void oqs_kem_frodokem_976_shake_pack(unsigned char *out, const size_t outlen, const uint16_t *in, const size_t inlen, const unsigned char lsb);
void oqs_kem_frodokem_976_shake_unpack(uint16_t *out, const size_t outlen, const unsigned char *in, const size_t inlen, const unsigned char lsb);

void oqs_kem_frodokem_1344_shake_pack(unsigned char *out, const size_t outlen, const uint16_t *in, const size_t inlen, const unsigned char lsb);
void oqs_kem_frodokem_1344_shake_unpack(uint16_t *out, const size_t outlen, const unsigned char *in, const size_t inlen, const unsigned char lsb);

void oqs_kem_frodokem_640_aes_pack(unsigned char *out, const size_t outlen, const uint16_t *in, const size_t inlen, const unsigned char lsb);
void oqs_kem_frodokem_640_aes_unpack(uint16_t *out, const size_t outlen, const unsigned char *in, const size_t inlen, const unsigned char lsb);

void oqs_kem_frodokem_976_aes_pack(unsigned char *out, const size_t outlen, const uint16_t *in, const size_t inlen, const unsigned char lsb);
void oqs_kem_frodokem_976_aes_unpack(uint16_t *out, const size_t outlen, const unsigned char *in, const size_t inlen, const unsigned char lsb);

void oqs_kem_frodokem_1344_aes_pack(unsigned char *out, const size_t outlen, const uint16_t *in, const size_t inlen, const unsigned char lsb);
void oqs_kem_frodokem_1344_aes_unpack(uint16_t *out, const size_t outlen, const unsigned char *in, const size_t inlen, const unsigned char lsb);

/* Kyber */

void pqcrystals_kyber512_avx2_pack_ciphertext(uint8_t *r, int16_t *b, int16_t *v);
void pqcrystals_kyber512_avx2_unpack_ciphertext(int16_t *b, int16_t *v, const uint8_t *c);

void pqcrystals_kyber512_ref_pack_ciphertext(uint8_t *r, int16_t *b, int16_t *v);
void pqcrystals_kyber512_ref_unpack_ciphertext(int16_t *b, int16_t *v, const uint8_t *c);

void pqcrystals_kyber512_90s_avx2_pack_ciphertext(uint8_t *r, int16_t *b, int16_t *v);
void pqcrystals_kyber512_90s_avx2_unpack_ciphertext(int16_t *b, int16_t *v, const uint8_t *c);

void pqcrystals_kyber512_90s_ref_pack_ciphertext(uint8_t *r, int16_t *b, int16_t *v);
void pqcrystals_kyber512_90s_ref_unpack_ciphertext(int16_t *b, int16_t *v, const uint8_t *c);

void pqcrystals_kyber768_avx2_pack_ciphertext(uint8_t *r, int16_t *b, int16_t *v);
void pqcrystals_kyber768_avx2_unpack_ciphertext(int16_t *b, int16_t *v, const uint8_t *c);

void pqcrystals_kyber768_ref_pack_ciphertext(uint8_t *r, int16_t *b, int16_t *v);
void pqcrystals_kyber768_ref_unpack_ciphertext(int16_t *b, int16_t *v, const uint8_t *c);

void pqcrystals_kyber768_90s_avx2_pack_ciphertext(uint8_t *r, int16_t *b, int16_t *v);
void pqcrystals_kyber768_90s_avx2_unpack_ciphertext(int16_t *b, int16_t *v, const uint8_t *c);

void pqcrystals_kyber768_90s_ref_pack_ciphertext(uint8_t *r, int16_t *b, int16_t *v);
void pqcrystals_kyber768_90s_ref_unpack_ciphertext(int16_t *b, int16_t *v, const uint8_t *c);

void pqcrystals_kyber1024_avx2_pack_ciphertext(uint8_t *r, int16_t *b, int16_t *v);
void pqcrystals_kyber1024_avx2_unpack_ciphertext(int16_t *b, int16_t *v, const uint8_t *c);

void pqcrystals_kyber1024_ref_pack_ciphertext(uint8_t *r, int16_t *b, int16_t *v);
void pqcrystals_kyber1024_ref_unpack_ciphertext(int16_t *b, int16_t *v, const uint8_t *c);

void pqcrystals_kyber1024_90s_avx2_pack_ciphertext(uint8_t *r, int16_t *b, int16_t *v);
void pqcrystals_kyber1024_90s_avx2_unpack_ciphertext(int16_t *b, int16_t *v, const uint8_t *c);

void pqcrystals_kyber1024_90s_ref_pack_ciphertext(uint8_t *r, int16_t *b, int16_t *v);
void pqcrystals_kyber1024_90s_ref_unpack_ciphertext(int16_t *b, int16_t *v, const uint8_t *c);


/* HQC */
void PQCLEAN_HQCRMRS128_CLEAN_hqc_pke_decrypt(uint8_t *m, const uint64_t *u, const uint64_t *v, const unsigned char *sk);
void PQCLEAN_HQCRMRS128_AVX2_hqc_pke_decrypt(uint8_t *m, const uint64_t *u, const uint64_t *v, const unsigned char *sk);
void PQCLEAN_HQCRMRS192_CLEAN_hqc_pke_decrypt(uint8_t *m, const uint64_t *u, const uint64_t *v, const unsigned char *sk);
void PQCLEAN_HQCRMRS192_AVX2_hqc_pke_decrypt(uint8_t *m, const uint64_t *u, const uint64_t *v, const unsigned char *sk);
void PQCLEAN_HQCRMRS256_CLEAN_hqc_pke_decrypt(uint8_t *m, const uint64_t *u, const uint64_t *v, const unsigned char *sk);
void PQCLEAN_HQCRMRS256_AVX2_hqc_pke_decrypt(uint8_t *m, const uint64_t *u, const uint64_t *v, const unsigned char *sk);

void PQCLEAN_HQCRMRS128_CLEAN_hqc_ciphertext_from_string(uint64_t *u, uint64_t *v, uint8_t *d, const uint8_t *ct);
void PQCLEAN_HQCRMRS128_AVX2_hqc_ciphertext_from_string(uint64_t *u, uint64_t *v, uint8_t *d, const uint8_t *ct);
void PQCLEAN_HQCRMRS192_CLEAN_hqc_ciphertext_from_string(uint64_t *u, uint64_t *v, uint8_t *d, const uint8_t *ct);
void PQCLEAN_HQCRMRS192_AVX2_hqc_ciphertext_from_string(uint64_t *u, uint64_t *v, uint8_t *d, const uint8_t *ct);
void PQCLEAN_HQCRMRS256_CLEAN_hqc_ciphertext_from_string(uint64_t *u, uint64_t *v, uint8_t *d, const uint8_t *ct);
void PQCLEAN_HQCRMRS256_AVX2_hqc_ciphertext_from_string(uint64_t *u, uint64_t *v, uint8_t *d, const uint8_t *ct);

void PQCLEAN_HQCRMRS128_CLEAN_hqc_pke_error_components(const unsigned char *m, uint64_t *r1, uint64_t *r2, uint64_t *e);
void PQCLEAN_HQCRMRS192_CLEAN_hqc_pke_error_components(const unsigned char *m, uint64_t *r1, uint64_t *r2, uint64_t *e);
void PQCLEAN_HQCRMRS256_CLEAN_hqc_pke_error_components(const unsigned char *m, uint64_t *r1, uint64_t *r2, uint64_t *e);

void PQCLEAN_HQCRMRS128_CLEAN_hqc_pke_decrypt_intermediates(uint8_t *m, uint8_t *rmencoded, uint8_t *rmdecoded, const uint64_t *u, const uint64_t *v, const unsigned char *sk);
void PQCLEAN_HQCRMRS192_CLEAN_hqc_pke_decrypt_intermediates(uint8_t *m, uint8_t *rmencoded, uint8_t *rmdecoded, const uint64_t *u, const uint64_t *v, const unsigned char *sk);
void PQCLEAN_HQCRMRS256_CLEAN_hqc_pke_decrypt_intermediates(uint8_t *m, uint8_t *rmencoded, uint8_t *rmdecoded, const uint64_t *u, const uint64_t *v, const unsigned char *sk);

void PQCLEAN_HQCRMRS128_CLEAN_hqc_pke_eprime(uint8_t *eprime, uint8_t *m, const uint64_t *u, const uint64_t *v, const unsigned char *sk);
void PQCLEAN_HQCRMRS192_CLEAN_hqc_pke_eprime(uint8_t *eprime, uint8_t *m, const uint64_t *u, const uint64_t *v, const unsigned char *sk);
void PQCLEAN_HQCRMRS256_CLEAN_hqc_pke_eprime(uint8_t *eprime, uint8_t *m, const uint64_t *u, const uint64_t *v, const unsigned char *sk);
