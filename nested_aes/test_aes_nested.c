#include <stdio.h>
#include <stdint.h>

#include <string.h>
#include <time.h>
#include <openssl/rand.h>

#include "aes_ctr.h"
#include "aes_gcm.h"
#include "AE_Nested_AES.h"

// This is a function for measuring timings
int main_timings() {
    printf("Start...\n");

    int size = 4096;
    int runs = 100;

    int total_re_encrypts = 128;

    int buffer_length = sizeof(AE_ctx_header) + size + total_re_encrypts * (2 * RHO + NU);
    printf("Buffer length is %d\n", buffer_length);
    uint8_t * message = (int8_t * ) malloc(size);
    RAND_bytes(message, size);
    uint8_t * decrypted_message1 = (int8_t * ) malloc(buffer_length);

    ct_hat_data_en ciphertext_hat1;
    uint8_t * ciphertext1 = (int8_t * ) malloc(buffer_length);
    ct_hat_data_en ciphertext_hat2;
    uint8_t * ciphertext2 = (int8_t * ) malloc(buffer_length);

    AE_key ae_key1, ae_key2;

    double gen_cycles = 0;
    double encrypt_cycles = 0;
    double regen_cycles = 0;
    double re_encrypt_cycles = 0;
    double decrypt_cycles[128] = {
        0
    };

    clock_t begin;
    clock_t end;

    for (int i = 0; i < runs; i++) {
        // AE_KeyGen
        begin = clock();
        AE_KeyGen( & ae_key1, total_re_encrypts);
        end = clock();
        gen_cycles += (double)(end - begin);

        // AE_Encrypt
        begin = clock();
        int ctx_length = AE_Encrypt( & ae_key1, message, & ciphertext_hat1, ciphertext1, size);
        end = clock();
        encrypt_cycles += (double)(end - begin);

        for (int re_encrypts = 0; re_encrypts < total_re_encrypts; re_encrypts++) {
            if (re_encrypts % 2 == 0) {
                // ReKeyGen
                begin = clock();
                AE_KeyGen( & ae_key2, total_re_encrypts);
                delta_token_data delta;
                AE_ReKeyGen( & ae_key1, & ae_key2, & ciphertext_hat1, & delta);
                end = clock();
                regen_cycles += (double)(end - begin);

                // ReEncrypt
                begin = clock();
                int reencrypt_length = AE_ReEncrypt( & delta, & ciphertext_hat1, ciphertext1, & ciphertext_hat2, ciphertext2, ctx_length);
                end = clock();
                re_encrypt_cycles += (double)(end - begin);

                // AE_Decrypt
                begin = clock();
                AE_Decrypt( & ae_key2, & ciphertext_hat2, ciphertext2, decrypted_message1, ctx_length);
                end = clock();
                decrypt_cycles[re_encrypts] += (double)(end - begin);

            } else {
                // ReKeyGen
                begin = clock();
                AE_KeyGen( & ae_key1, total_re_encrypts);
                delta_token_data delta;
                AE_ReKeyGen( & ae_key2, & ae_key1, & ciphertext_hat2, & delta);
                end = clock();
                regen_cycles += (double)(end - begin);

                // ReEncrypt
                begin = clock();
                int reencrypt_length = AE_ReEncrypt( & delta, & ciphertext_hat2, ciphertext2, & ciphertext_hat1, ciphertext1, ctx_length);
                end = clock();
                re_encrypt_cycles += (double)(end - begin);

                // AE_Decrypt
                begin = clock();
                AE_Decrypt( & ae_key1, & ciphertext_hat1, ciphertext1, decrypted_message1, ctx_length);
                end = clock();
                decrypt_cycles[re_encrypts] += (double)(end - begin);

            }
        }
    }

    gen_cycles /= CLOCKS_PER_SEC;
    encrypt_cycles /= CLOCKS_PER_SEC;
    regen_cycles /= CLOCKS_PER_SEC;
    re_encrypt_cycles /= CLOCKS_PER_SEC;
    for (int i = 0; i < 128; i++) decrypt_cycles[i] /= CLOCKS_PER_SEC;

    printf("NESTED AES GCM Size:%d Runs:%u\n gen_key:    %f %d\n encrypt:    %f %d\n regen_key:  %f %d\n re_encrypt: %f %d\n\n ",
        size, runs,
        gen_cycles, runs,
        encrypt_cycles, runs,
        regen_cycles, (runs * total_re_encrypts),
        re_encrypt_cycles, (runs * total_re_encrypts));

    printf("Decrypt Data\n");
    for (int i = 0; i < 128; i++) printf("%f, ", decrypt_cycles[i]);
    printf("\n");

    free(message);
    free(decrypted_message1);
    free(ciphertext1);
    free(ciphertext2);
    printf("Done...\n");
}

int main() {
    main_timings();
}