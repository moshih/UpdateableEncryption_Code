#include <stdio.h>

#include <stdint.h>

#include <string.h>

#include <time.h>

#include <openssl/rand.h>

#include "aes_ctr.h"

#include "aes_gcm.h"

#include "AE_Nested_AES.h"

void AE_KeyGen(AE_key * ae_key, int t) {
    RAND_bytes(ae_key->key, 16);
    ae_key->k_t = t;
}

int AE_Encrypt(AE_key * ae_key, uint8_t * message, ct_hat_data_en * ciphertext_hat, uint8_t * ciphertext, int length) {
    ct_hat_data meta;

    for (int i = 0; i < KEY_LEN; i++) meta.history_key[i] = 0;

    // key for ct_payload
    RAND_bytes(meta.payload_key, KEY_LEN);

    // encrypts fot ct_payload
    AE_ctx_header * ct_payload_header = (AE_ctx_header * ) ciphertext;
    RAND_bytes(ct_payload_header->iv, IV_LEN);
    int ctx_length = gcm_encrypt(message, length,
        meta.payload_key,
        ct_payload_header->iv, IV_LEN,
        ciphertext + sizeof(AE_ctx_header),
        ct_payload_header->tag);
    if (ctx_length != length) printf("AE Encrypt failed!");
    meta.ct_payload_length = ctx_length;

    // generating ct_pad
    RAND_bytes(meta.prg_seed, SEED_LEN);

    int gen_len = prg_aes_ctr(ciphertext + sizeof(AE_ctx_header) + length, meta.prg_seed, ae_key->k_t * (2 * RHO + NU));
    if (gen_len != (ae_key->k_t * (2 * RHO + NU))) printf("Gen failed!\n");

    // encrypts fot ciphertext_hat
    RAND_bytes(ciphertext_hat->header.iv, IV_LEN);
    int ctx_hat_length = gcm_encrypt((uint8_t * ) & meta, sizeof(ct_hat_data),
        ae_key->key,
        ciphertext_hat->header.iv, IV_LEN,
        ciphertext_hat->data,
        ciphertext_hat->header.tag);
    if (ctx_hat_length != sizeof(ct_hat_data)) printf("ctx hat encryption failed!\n");
    return ctx_length + gen_len;
}

int decrypt_last_step(uint8_t * ct_payload, uint8_t * payload_key, uint8_t * history_key, int length, uint8_t * message, uint8_t * data) {
    uint8_t key_and = 0;
    for (int i = 0; i < KEY_LEN; i++) key_and |= history_key[i];

    if (key_and == 0) {
        AE_ctx_header * ct_payload_header = (AE_ctx_header * ) ct_payload;
        int decrypt_payload_len = gcm_decrypt(ct_payload + sizeof(AE_ctx_header), length,
            ct_payload_header->tag,
            payload_key,
            ct_payload_header->iv, IV_LEN,
            message);
        if (decrypt_payload_len != length) {
            printf("ERROR: DECRYPTING PAYLOAD %d %d\n", decrypt_payload_len, length);
            return -1;
        }
    } else {
        AE_ctx_header * ct_payload_header = (AE_ctx_header * ) ct_payload;
        int decrypt_payload_len = gcm_decrypt(ct_payload + sizeof(AE_ctx_header), length,
            ct_payload_header->tag,
            payload_key,
            ct_payload_header->iv, IV_LEN,
            data);
        if (decrypt_payload_len != length) {
            printf("ERROR: DECRYPTING PAYLOAD %d %d\n", decrypt_payload_len, length);
            return -1;
        }

        int8_t * ct_history = data + (length - sizeof(AE_ctx_header) - 2 * KEY_LEN);
        int8_t decrypt_ct_history[2 * KEY_LEN] = {
            0
        };
        int decrypt_ct_history_len = gcm_decrypt(ct_history + sizeof(AE_ctx_header), 2 * KEY_LEN,
            ct_history + IV_LEN,
            history_key,
            ct_history, IV_LEN,
            decrypt_ct_history);
        if (decrypt_ct_history_len != 2 * KEY_LEN) {
            printf("ERROR: DECRYPTING CT HISTORY %d\n", decrypt_ct_history_len);
            return -1;
        }
        decrypt_last_step(data, decrypt_ct_history, decrypt_ct_history + KEY_LEN, (length - 2 * sizeof(AE_ctx_header) - 2 * KEY_LEN), message, ct_payload);
    }
    return 0;
}

void AE_Decrypt(AE_key * ae_key, ct_hat_data_en * ciphertext_hat, uint8_t * ciphertext, uint8_t * message, int ctx_length) {
    ct_hat_data meta;

    // Step 1
    int meta_decrypt = gcm_decrypt(ciphertext_hat->data, sizeof(ct_hat_data),
        ciphertext_hat->header.tag,
        ae_key->key,
        ciphertext_hat->header.iv, IV_LEN,
        (uint8_t * ) & meta);
    if (meta_decrypt != sizeof(ct_hat_data)) {
        printf("ctx header decryption failed!\n");
        return;
    }

    // Step 2
    if (meta.ct_payload_length > ctx_length) {
        printf("DECRYPT FAILED: mismatch of payload length\n");
        return;
    }

    uint8_t * ct_payload = ciphertext;
    uint8_t * ct_pad = ciphertext + sizeof(AE_ctx_header) + meta.ct_payload_length;

    // Step 3
    int pad_len = ctx_length - meta.ct_payload_length;
    uint8_t * gen_pad = malloc(pad_len);
    int gen_len = prg_aes_ctr(gen_pad, meta.prg_seed, pad_len);
    if (gen_len != pad_len) printf("Gen failed! %d %d\n", gen_len, pad_len);

    for (int i = 0; i < pad_len; i++) {
        if (gen_pad[i] != ct_pad[i]) {
            printf("ERROR PAD MISMATCH\n");
            free(gen_pad);
            return;
        }
    }
    free(gen_pad);

    // Step 4 part a
    uint8_t * payload = malloc(meta.ct_payload_length + sizeof(AE_ctx_header));
    memcpy(payload, ct_payload, meta.ct_payload_length + sizeof(AE_ctx_header));
    uint8_t * data = malloc(meta.ct_payload_length);
    decrypt_last_step(payload, meta.payload_key, meta.history_key, meta.ct_payload_length, message, data);
    free(data);
    free(payload);
}

int AE_ReKeyGen(AE_key * ae_key1, AE_key * ae_key2, ct_hat_data_en * ciphertext_hat, delta_token_data * delta) {
    ct_hat_data old_meta;

    // Step 1
    int meta_decrypt = gcm_decrypt(ciphertext_hat->data, sizeof(ct_hat_data),
        ciphertext_hat->header.tag,
        ae_key1->key,
        ciphertext_hat->header.iv, IV_LEN,
        (uint8_t * ) & old_meta);
    if (meta_decrypt != sizeof(ct_hat_data)) {
        printf("ctx header decryption failed!\n");
        return -1;
    }

    ct_hat_data new_meta;

    // Step 2
    RAND_bytes(new_meta.history_key, KEY_LEN);
    RAND_bytes(delta->ct_hat_history_header.iv, IV_LEN);
    int ct_hat_history_length = gcm_encrypt_2(old_meta.payload_key, KEY_LEN,
        old_meta.history_key, KEY_LEN,
        new_meta.history_key,
        delta->ct_hat_history_header.iv, IV_LEN,
        (uint8_t * ) & delta->ct_hat_history,
        delta->ct_hat_history_header.tag);

    // Step 3
    RAND_bytes(new_meta.payload_key, KEY_LEN);
    RAND_bytes(new_meta.prg_seed, SEED_LEN);
    for (int i = 0; i < KEY_LEN; i++) {
        delta->key_ae[i] = new_meta.payload_key[i];
        delta->prg_seed[i] = new_meta.prg_seed[i];
    }

    new_meta.ct_payload_length = old_meta.ct_payload_length + 2 * sizeof(AE_ctx_header) + ct_hat_history_length;
    RAND_bytes(delta->ct_hat_data_header.iv, IV_LEN);
    int ct_hat_prime_length = gcm_encrypt((uint8_t * ) & new_meta, sizeof(ct_hat_data),
        ae_key2->key,
        delta->ct_hat_data_header.iv, IV_LEN,
        (uint8_t * ) & delta->ct_hat,
        delta->ct_hat_data_header.tag);
    delta->length = old_meta.ct_payload_length;
    return 0;
}

int AE_ReEncrypt(delta_token_data * delta, ct_hat_data_en * ciphertext_hat1, uint8_t * ciphertext1, ct_hat_data_en * ciphertext_hat2, uint8_t * ciphertext2, int ctx_length) {
    if (delta->length > ctx_length) {
        printf("ERROR: payload lenght too big!\n");
        return -1;
    }

    uint8_t * ciphertext1_payload = ciphertext1 + sizeof(AE_ctx_header);
    uint8_t * ciphertext1_pad = ciphertext1 + sizeof(AE_ctx_header) + delta->length;

    AE_ctx_header * ct_payload_header = (AE_ctx_header * ) ciphertext2;
    RAND_bytes(ct_payload_header->iv, IV_LEN);
    int ct_payload_length = gcm_encrypt_4(ciphertext1, sizeof(AE_ctx_header),
        ciphertext1_payload, delta->length,
        (uint8_t * ) & delta->ct_hat_history_header, sizeof(AE_ctx_header),
        (uint8_t * ) & delta->ct_hat_history, 2 * KEY_LEN,
        (uint8_t * ) & delta->key_ae,
        ct_payload_header->iv, IV_LEN,
        ciphertext2 + sizeof(AE_ctx_header),
        ct_payload_header->tag);
    if (ct_payload_length != sizeof(AE_ctx_header) + delta->length + sizeof(AE_ctx_header) + 2 * KEY_LEN) {
        printf("ct_payload_length encryption failed!\n");
        return -1;
    }
    int gen_len = prg_aes_ctr(ciphertext2 + sizeof(AE_ctx_header) + ct_payload_length, delta->prg_seed, (ctx_length - ct_payload_length));
    if (gen_len != (ctx_length - ct_payload_length)) printf("Gen failed!! %d %d", gen_len, (ctx_length - ct_payload_length));

    memcpy(ciphertext_hat2, & delta->ct_hat_data_header, sizeof(AE_ctx_header));
    memcpy(ciphertext_hat2->data, & delta->ct_hat, sizeof(ct_hat_data));
    return ctx_length;
}