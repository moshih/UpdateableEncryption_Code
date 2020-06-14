#include <stdio.h>
#include <stdint.h>

#include <string.h>
#include <openssl/rand.h>

#include "aes_gcm.h"
#include "ntt.h"

typedef struct AE_ctx_header AE_ctx_header;
typedef struct UAE_lwe_data_header UAE_lwe_data_header;
typedef struct UAE_lwe_ctx_header UAE_lwe_ctx_header;
typedef struct UAE_lwe_delta UAE_lwe_delta;

struct AE_ctx_header
{
  uint8_t iv[IV_LEN]; // this value should be random
  uint8_t tag[TAG_LEN]; // set by AES GCM
};

struct UAE_lwe_data_header
{
  poly_28 poly_key;
  uint8_t hash[SHAKE128_RATE]; // set by AES GCM
};

struct UAE_lwe_ctx_header
{
  uint8_t iv[IV_LEN]; // this value should be random
  uint8_t tag[TAG_LEN]; // set by AES GCM
  uint8_t ctx[sizeof(UAE_lwe_data_header)]; // set by AES GCM
};

struct UAE_lwe_delta
{
  UAE_lwe_ctx_header ctx_header;
  poly_28 poly_key;
};

void mult_poly_ntru(poly_28 *result, poly_28 *poly_a, poly_28 *poly_b);

void poly_uniform_ref_message(unsigned char *a, const unsigned char *seed, unsigned int size);

void poly_uniform_ref_poly_28(poly_28 *a, const unsigned char *seed);
void poly_uniform_ref_poly_28_avx(poly_28 *a, const unsigned char *seed);
void poly_uniform_ref_noise_12_2_seeds_pseudo(poly_28 *a, const unsigned char *seed);
void poly_uniform_ref_noise_12_2_seeds_pseudo_avx(poly_28 *a, const unsigned char *seed);

void create_product_point(poly_28 *key_point_poly,poly_28 *product_point_poly, unsigned char*point_seed);
void create_product_point_avx(poly_28 *key_point_poly,poly_28 *product_point_poly, unsigned char*point_seed);

void lwe_gen_key(poly_28 *key_point_poly);
void lwe_gen_key_avx(poly_28 *key_point_poly);

void kh_prf_encrypt(poly_28 *key_point_poly,uint8_t *buf, unsigned int size);
void kh_prf_re_encrypt(poly_28 *key_point_poly_1, poly_28 *key_point_poly_2,  uint8_t *test_array, unsigned int size);

void kh_prf_encrypt_avx(poly_28 *key_point_poly,uint8_t *buf, unsigned int size);
void kh_prf_decrypt_avx(poly_28 *key_point_poly,uint8_t *buf, unsigned int size);
void kh_prf_re_encrypt_avx(poly_28 *key_point_poly_1, poly_28 *key_point_poly_2,  uint8_t *test_array, unsigned int size);

int kh_prf_encrypt_2(poly_28 *key_point_poly, uint8_t *buf, uint8_t *out, unsigned int size);
int kh_prf_decrypt_2(poly_28 *key_point_poly, uint8_t *buf, uint8_t *out, unsigned int size);
int kh_prf_re_encrypt_2(poly_28 *key_point_poly, uint8_t *buf, uint8_t *out, unsigned int size);

int kh_prf_encrypt_2_avx(poly_28 *key_point_poly, uint8_t *buf, uint8_t *out, unsigned int size);
int kh_prf_decrypt_2_avx(poly_28 *key_point_poly, uint8_t *buf, uint8_t *out, unsigned int size);
int kh_prf_re_encrypt_2_avx(poly_28 *key_point_poly, uint8_t *buf, uint8_t *out, unsigned int size);

void UAE_Keygen(int8_t *AE_key);
int UAE_Encrypt(int8_t *AE_key,uint8_t *message, UAE_lwe_ctx_header* ciphertext_hat, uint8_t* ciphertext, unsigned int size);
int UAE_Decrypt(int8_t *AE_key,uint8_t *decrypted_message, UAE_lwe_ctx_header* ciphertext_hat, uint8_t* ciphertext, unsigned int size);
int UAE_ReKeygen(int8_t *AE_key1,int8_t *AE_key2, UAE_lwe_ctx_header* ciphertext_hat, UAE_lwe_delta* delta);
int UAE_ReKeygen_avx(int8_t *AE_key1, int8_t *AE_key2, UAE_lwe_ctx_header *ciphertext_hat, UAE_lwe_delta *delta);
int UAE_ReEncrypt(UAE_lwe_delta* delta, 
  UAE_lwe_ctx_header* ciphertext_hat1, uint8_t* ciphertext1, 
  UAE_lwe_ctx_header* ciphertext_hat2, uint8_t* ciphertext2, unsigned int size);
int UAE_Encrypt_avx(int8_t *AE_key,uint8_t *message, UAE_lwe_ctx_header* ciphertext_hat, uint8_t* ciphertext, unsigned int size);
int UAE_Decrypt_avx(int8_t *AE_key,uint8_t *decrypted_message, UAE_lwe_ctx_header* ciphertext_hat, uint8_t* ciphertext, unsigned int size);
int UAE_ReEncrypt_avx(UAE_lwe_delta* delta, 
  UAE_lwe_ctx_header* ciphertext_hat1, uint8_t* ciphertext1, 
  UAE_lwe_ctx_header* ciphertext_hat2, uint8_t* ciphertext2, unsigned int size);