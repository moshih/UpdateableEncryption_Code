#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include "crypto_algorithms.h"

void main()
{
    printf("Start...\n");
    int size = 4096;
    int runs = 1000;
    int total_re_encrypts = 128;

    uint8_t *message = malloc(size + (PAD_SIZE - (size % PAD_SIZE)));
    RAND_bytes(message, size);
    uint8_t *ctx1 = malloc(3 *size);
    uint8_t *ctx2 = malloc(3 *size);
    uint8_t *decrypted_message1 = malloc(size + (PAD_SIZE - (size % PAD_SIZE)));
    uint8_t *decrypted_message2 = malloc(size + (PAD_SIZE - (size % PAD_SIZE)));

    uint8_t AE_key1[AE_KEY_LEN];
    UAE_lwe_ctx_header ctx_hat1;
    uint8_t AE_key2[AE_KEY_LEN];
    UAE_lwe_delta delta1;
    UAE_lwe_ctx_header ctx_hat2;

    int rekeygen_output;
    int re_encrypt_length;

    double gen_cycles = 0;
    double encrypt_cycles = 0;
    double regen_cycles = 0;
    double re_encrypt_cycles = 0;
    double decrypt_cycles[128] = { 0 };

    clock_t begin;
    clock_t end;

    for (int j = 0; j < runs; j++)
    {
        // KeyGen
        begin = clock();
        UAE_Keygen(AE_key1);
        end = clock();
        gen_cycles += (double)(end - begin);

        // Encrypt
        begin = clock();
        int padded_size = UAE_Encrypt(AE_key1, message, &ctx_hat1, ctx1, size);
        end = clock();
        encrypt_cycles += (double)(end - begin);

        for (int i = 0; i < total_re_encrypts; i++)
        {
            if (i % 2 == 0)
            {
                // ReKeyGen
                begin = clock();
                UAE_Keygen(AE_key2);
                rekeygen_output = UAE_ReKeygen(AE_key1, AE_key2, &ctx_hat1, &delta1);
                end = clock();
                regen_cycles += (double)(end - begin);

                // ReEncrypt
                begin = clock();
                re_encrypt_length = UAE_ReEncrypt(&delta1, &ctx_hat1, ctx1, &ctx_hat2, ctx2, padded_size);
                end = clock();
                re_encrypt_cycles += (double)(end - begin);

                // Decrypt
                begin = clock();
                int decrypted_size1 = UAE_Decrypt(AE_key1, decrypted_message1, &ctx_hat1, ctx1, re_encrypt_length);
                end = clock();
                decrypt_cycles[i] += (double)(end - begin);
            }
            else
            {
                // ReKeyGen
                begin = clock();
                UAE_Keygen(AE_key1);
                rekeygen_output = UAE_ReKeygen(AE_key2, AE_key1, &ctx_hat2, &delta1);
                end = clock();
                regen_cycles += (double)(end - begin);

                // ReEncrypt
                begin = clock();
                re_encrypt_length = UAE_ReEncrypt(&delta1, &ctx_hat2, ctx2, &ctx_hat1, ctx1, padded_size);
                end = clock();
                re_encrypt_cycles += (double)(end - begin);

                // Decrypt
                begin = clock();
                int decrypted_size2 = UAE_Decrypt(AE_key2, decrypted_message2, &ctx_hat2, ctx2, re_encrypt_length);
                end = clock();
                decrypt_cycles[i] += (double)(end - begin);
            }
        }
    }

    gen_cycles /= CLOCKS_PER_SEC;
    encrypt_cycles /= CLOCKS_PER_SEC;
    regen_cycles /= CLOCKS_PER_SEC;
    re_encrypt_cycles /= CLOCKS_PER_SEC;
    for (int i = 0; i < 128; i++) decrypt_cycles[i] /= CLOCKS_PER_SEC;
    //decrypt_cycles /=CLOCKS_PER_SEC;

    printf("UAE 128 Size:%d Runs:%u\n gen_key:    %f %d\n encrypt:    %f %d\n regen_key:  %f %d\n re_encrypt: %f %d\n\n ",
        size, runs,
        gen_cycles, runs,
        encrypt_cycles, runs,
        regen_cycles, (runs *total_re_encrypts),
        re_encrypt_cycles, (runs *total_re_encrypts));

    printf("Decrypt Data\n");
    for (int i = 0; i < 128; i++) printf("%f, ", decrypt_cycles[i]);
    printf("\n");

    free(message);
    free(ctx1);
    free(ctx2);
    free(decrypted_message1);
    free(decrypted_message2);
    printf("Done...\n");
}