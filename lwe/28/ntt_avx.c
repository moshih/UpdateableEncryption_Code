#include "ntt_avx.h"

void ntt_avx(int32_t * r,
    const int32_t * zetas_asm) {
    int i;
    for (i = 0; i < 512; i += 32) ntt_level0_avx_s32(r + i, & zetas_asm[1]);

    int zeta_i;

    for (i = 0; i < 768; i += 32) {
        if (i % 512 >= 256) continue;

        zeta_i = 2 + (i >> 9);
        ntt_level1_avx_s32(r + i, & zetas_asm[zeta_i]);
    }

    for (i = 0; i < 896; i += 32) {
        if (i % 256 >= 128) continue;

        zeta_i = 4 + (i >> 8);
        ntt_level2_avx_s32(r + i, & zetas_asm[zeta_i]);
    }

    for (i = 0; i < 960; i += 32) {
        if (i % 128 >= 64) continue;

        zeta_i = 8 + (i >> 7);
        ntt_level3_avx_s32(r + i, & zetas_asm[zeta_i]);
    }

    for (i = 0; i < 992; i += 32) {
        if (i % 64 >= 32) continue;

        zeta_i = 16 + (i >> 6);
        ntt_level4_avx_s32(r + i, & zetas_asm[zeta_i]);
    }

    for (i = 0; i < 1024; i += 64) {
        zeta_i = 32 + 2 * (i >> 6);
        ntt_level5_avx_s32(r + i, & zetas_asm[zeta_i]);
    }

    for (i = 0; i < 1024; i += 64) {
        zeta_i = 64 + 4 * (i >> 6);
        ntt_level6_avx_s32(r + i, & zetas_asm[zeta_i]);
    }

    for (i = 0; i < 1024; i += 64) {
        zeta_i = 128 + 32 * (i >> 6);
        ntt_level7_avx_s32(r + i, & zetas_asm[zeta_i]);
    }

    for (i = 0; i < 1024; i += 64) {
        zeta_i = 641 + 32 * (i >> 6);
        ntt_level8_avx_s32(r + i, & zetas_asm[zeta_i]);
    }
}

void inv_ntt_avx(int32_t * r,
    const int32_t * zetas_inv_asm) {
    int zeta_i, i;

    for (i = 0; i < 1024; i += 64) {
        zeta_i = 32 * (i >> 6);
        invntt_level0_avx_s32(r + i, & zetas_inv_asm[zeta_i]);
    }

    for (i = 0; i < 1024; i += 64) {
        zeta_i = 512 + 32 * (i >> 6);
        invntt_level1_avx_s32(r + i, & zetas_inv_asm[zeta_i]);
    }

    for (i = 0; i < 1024; i += 64) {
        zeta_i = 1024 + 4 * (i >> 6);
        invntt_level2_avx_s32(r + i, & zetas_inv_asm[zeta_i]);
    }

    for (i = 0; i < 1024; i += 64) {
        zeta_i = 1088 + 2 * (i >> 6);
        invntt_level3_avx_s32(r + i, & zetas_inv_asm[zeta_i]);
    }

    for (i = 0; i < 992; i += 32) {
        if (i % 64 >= 32) continue;

        zeta_i = 1120 + (i >> 6);
        invntt_level4_avx_s32(r + i, & zetas_inv_asm[zeta_i]);
    }

    for (i = 0; i < 960; i += 32) {
        if (i % 128 >= 64) continue;

        zeta_i = 1136 + (i >> 7);
        invntt_level5_avx_s32(r + i, & zetas_inv_asm[zeta_i]);
    }

    // 896 = 1024-128
    for (i = 0; i < 896; i += 32) {
        if (i % 256 >= 128) continue;

        zeta_i = 1144 + (i >> 8);
        invntt_level6_avx_s32(r + i, & zetas_inv_asm[zeta_i]);
    }

    for (i = 0; i < 768; i += 32) {
        if (i % 512 >= 256) continue;

        zeta_i = 1148 + (i >> 9);
        invntt_level7_avx_s32(r + i, & zetas_inv_asm[zeta_i]);
    }

    for (i = 0; i < 512; i += 32) invntt_level8_avx_s32(r + i, & zetas_inv_asm[1150]);

}