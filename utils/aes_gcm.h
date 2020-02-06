#include <stdint.h>

int gcm_encrypt(uint8_t *plaintext, int plaintext_len,
                uint8_t *key,
                uint8_t *iv, int iv_len,
                uint8_t *ciphertext,
                uint8_t *tag);

int gcm_encrypt_2(uint8_t *plaintext_1, int plaintext_len_1,
				uint8_t *plaintext_2, int plaintext_len_2,
                uint8_t *key,
                uint8_t *iv, int iv_len,
                uint8_t *ciphertext,
                uint8_t *tag);

int gcm_encrypt_4(uint8_t *plaintext_1, int plaintext_len_1,
                uint8_t *plaintext_2, int plaintext_len_2,
                uint8_t *plaintext_3, int plaintext_len_3,
                uint8_t *plaintext_4, int plaintext_len_4,
                uint8_t *key,
                uint8_t *iv, int iv_len,
                uint8_t *ciphertext,
                uint8_t *tag);

int gcm_decrypt(uint8_t *ciphertext, int ciphertext_len,
                uint8_t *tag,
                uint8_t *key,
                uint8_t *iv, int iv_len,
                uint8_t *plaintext);