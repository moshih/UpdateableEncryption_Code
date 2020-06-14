#include "ntt_avx_268369921.h"

void ntt_avx_268369921(int32_t * r,
    const int32_t * zetas_asm) {
    int i;
    int zeta_i;
 
    for (i = 0; i < 512*2; i += 32) ntt_level0_avx_s32_268369921(r + i, & zetas_asm[1]);

    for (i = 0; i < 768*2; i += 32) {
        if (i % 1024 >= 512) continue;

        zeta_i = 2 + (i >> 10);
        ntt_level1_avx_s32_268369921(r + i, & zetas_asm[zeta_i]);
    }

    for (i = 0; i < 896*2; i += 32) {
        if (i % 512 >= 256) continue;

        zeta_i = 4 + (i >> 9);
        ntt_level2_avx_s32_268369921(r + i, & zetas_asm[zeta_i]);
    }

    for (i = 0; i < 960*2; i += 32) {
        if (i % 256 >= 128) continue;

        zeta_i = 8 + (i >> 8);
        ntt_level3_avx_s32_268369921(r + i, & zetas_asm[zeta_i]);
    }

    for (i = 0; i < 992*2; i += 32) {
        if (i % 128 >= 64) continue;

        zeta_i = 16 + (i >> 7);
        ntt_level4_avx_s32_268369921(r + i, & zetas_asm[zeta_i]);
    }

    for (i = 0; i < 1008*2; i += 32) {
        if (i % 64 >= 32) continue;

        zeta_i = 32 + (i >> 6);
        ntt_level5_avx_s32_268369921(r + i, & zetas_asm[zeta_i]);
    }

    for (i = 0; i < 1024*2; i += 64) {
        zeta_i = 64 + 2 * (i >> 6);
        ntt_level6_avx_s32_268369921(r + i, & zetas_asm[zeta_i]);
    }

    for (i = 0; i < 1024*2; i += 64) {
        zeta_i = 128 + 4 * (i >> 6);
        ntt_level7_avx_s32_268369921(r + i, & zetas_asm[zeta_i]);
    }

    for (i = 0; i < 1024*2; i += 64) {
        zeta_i = 256 + 32 * (i >> 6);
        ntt_level8_avx_s32_268369921(r + i, & zetas_asm[zeta_i]);
    }
    
    for (i = 0; i < 1024*2; i += 64) {
        zeta_i = 1281 + 32 * (i >> 6);
        ntt_level9_avx_s32_268369921(r + i, & zetas_asm[zeta_i]);
    }
    
}

void inv_ntt_avx_268369921(int32_t * r,
    const int32_t * zetas_inv_asm) {
    int zeta_i, i;

    for (i = 0; i < 1024*2; i += 64) {
        zeta_i = 32 * (i >> 6);
        invntt_level0_avx_s32_268369921(r + i, & zetas_inv_asm[zeta_i]);
    }

    for (i = 0; i < 1024*2; i += 64) {
        zeta_i = 1024 + 32 * (i >> 6);
        invntt_level1_avx_s32_268369921(r + i, & zetas_inv_asm[zeta_i]);
    }

    for (i = 0; i < 1024*2; i += 64) {
        zeta_i = 1024*2 + 4 * (i >> 6);
        invntt_level2_avx_s32_268369921(r + i, & zetas_inv_asm[zeta_i]);
    }

    for (i = 0; i < 1024*2; i += 64) {
        zeta_i = (1024+64)*2 + 2 * (i >> 6);
        invntt_level3_avx_s32_268369921(r + i, & zetas_inv_asm[zeta_i]);
    }

    for (i = 0; i < 1008*2; i += 32) {
        if (i % 64 >= 32) continue;

        zeta_i = (1024+64+32)*2 + (i >> 6);
        invntt_level4_avx_s32_268369921(r + i, & zetas_inv_asm[zeta_i]);
    }

    for (i = 0; i < 992*2; i += 32) {
        if (i % 128 >= 64) continue;

        zeta_i = (1024+64+32+16)*2 + (i >> 7);
        invntt_level5_avx_s32_268369921(r + i, & zetas_inv_asm[zeta_i]);
    }

    for (i = 0; i < 960*2; i += 32) {
        if (i % 256 >= 128) continue;

        zeta_i = (1024+64+32+16+8)*2 + (i >> 8);
        invntt_level6_avx_s32_268369921(r + i, & zetas_inv_asm[zeta_i]);
    }

    for (i = 0; i < 896*2; i += 32) {
        if (i % 512 >= 256) continue;

        zeta_i = (1024+64+32+16+8+4)*2 + (i >> 9);
        invntt_level7_avx_s32_268369921(r + i, & zetas_inv_asm[zeta_i]);
    }

    for (i = 0; i < 768*2; i += 32) {
        if (i % 1024 >= 512) continue;

        zeta_i = (1024+64+32+16+8+4+2)*2 + (i >> 10);
        invntt_level8_avx_s32_268369921(r + i, & zetas_inv_asm[zeta_i]);
    }

    for (i = 0; i < 512*2; i += 32) invntt_level9_avx_s32_268369921(r + i, & zetas_inv_asm[2302]);
}