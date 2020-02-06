#include <stdint.h>

int ctr_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext);

int ctr_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext);

int prg_aes_ctr(uint8_t *buffer, uint8_t *key, unsigned int size);