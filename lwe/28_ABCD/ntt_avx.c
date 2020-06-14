#include "ntt_avx.h"

void inv_ntt_avx_268369921(int32_t * r,
    const int32_t * zetas_inv_asm) {
    int zeta_i, i;

    for (i = 0; i < 1024*4; i += 64) {
        zeta_i = 32 * (i >> 6);
        invntt_level0_avx_s32_268369921(r + i, & zetas_inv_asm[zeta_i]);
    }

    for (i = 0; i < 1024*4; i += 64) {
        zeta_i = 1024*2 + 32 * (i >> 6);
        invntt_level1_avx_s32_268369921(r + i, & zetas_inv_asm[zeta_i]);
    }

    for (i = 0; i < 1024*4; i += 64) {
        zeta_i = 1024*4 + 4 * (i >> 6);
        invntt_level2_avx_s32_268369921(r + i, & zetas_inv_asm[zeta_i]);
    }
    for (i = 0; i < 1024*4; i += 64) {
        zeta_i = (1024+64)*4 + 2 * (i >> 6);
        invntt_level3_avx_s32_268369921(r + i, & zetas_inv_asm[zeta_i]);
    }
    for (i = 0; i < 1016*4; i += 32) {
        if (i % 64 >= 32) continue;

        zeta_i = (1024+64+32)*4 + (i >> 6);
        invntt_level4_avx_s32_268369921(r + i, & zetas_inv_asm[zeta_i]);
    }

    for (i = 0; i < 1008*4; i += 32) {
        if (i % 128 >= 64) continue;

        zeta_i = (1024+64+32+16)*4 + (i >> 7);
        invntt_level5_avx_s32_268369921(r + i, & zetas_inv_asm[zeta_i]);
    }

    for (i = 0; i < 992*4; i += 32) {
        if (i % 256 >= 128) continue;

        zeta_i = (1024+64+32+16+8)*4 + (i >> 8);
        invntt_level6_avx_s32_268369921(r + i, & zetas_inv_asm[zeta_i]);
    }

    for (i = 0; i < 960*4; i += 32) {
        if (i % 512 >= 256) continue;

        zeta_i = (1024+64+32+16+8+4)*4 + (i >> 9);
        invntt_level7_avx_s32_268369921(r + i, & zetas_inv_asm[zeta_i]);
    }

    for (i = 0; i < 896*4; i += 32) {
        if (i % 1024 >= 512) continue;

        zeta_i = (1024+64+32+16+8+4+2)*4 + (i >> 10);
        invntt_level8_avx_s32_268369921(r + i, & zetas_inv_asm[zeta_i]);
    }

    for (i = 0; i < 768*4; i += 32) {
        if (i % 2048 >= 1024) continue;

        zeta_i = (1024+64+32+16+8+4+2+1)*4 + (i >> 11);
        invntt_level9_avx_s32_268369921(r + i, & zetas_inv_asm[zeta_i]);
    }
    for (i = 0; i < 512*4; i += 32) invntt_level10_avx_s32_268369921(r + i, & zetas_inv_asm[4606]);
    return;
}

void inv_ntt_avx_268361729(int32_t * r,
    const int32_t * zetas_inv_asm) {
    int zeta_i, i;

    for (i = 0; i < 1024*4; i += 64) {
        zeta_i = 32 * (i >> 6);
        invntt_level0_avx_s32_268361729(r + i, & zetas_inv_asm[zeta_i]);
    }

    for (i = 0; i < 1024*4; i += 64) {
        zeta_i = 1024*2 + 32 * (i >> 6);
        invntt_level1_avx_s32_268361729(r + i, & zetas_inv_asm[zeta_i]);
    }

    for (i = 0; i < 1024*4; i += 64) {
        zeta_i = 1024*4 + 4 * (i >> 6);
        invntt_level2_avx_s32_268361729(r + i, & zetas_inv_asm[zeta_i]);
    }
    for (i = 0; i < 1024*4; i += 64) {
        zeta_i = (1024+64)*4 + 2 * (i >> 6);
        invntt_level3_avx_s32_268361729(r + i, & zetas_inv_asm[zeta_i]);
    }
    for (i = 0; i < 1016*4; i += 32) {
        if (i % 64 >= 32) continue;

        zeta_i = (1024+64+32)*4 + (i >> 6);
        invntt_level4_avx_s32_268361729(r + i, & zetas_inv_asm[zeta_i]);
    }

    for (i = 0; i < 1008*4; i += 32) {
        if (i % 128 >= 64) continue;

        zeta_i = (1024+64+32+16)*4 + (i >> 7);
        invntt_level5_avx_s32_268361729(r + i, & zetas_inv_asm[zeta_i]);
    }

    for (i = 0; i < 992*4; i += 32) {
        if (i % 256 >= 128) continue;

        zeta_i = (1024+64+32+16+8)*4 + (i >> 8);
        invntt_level6_avx_s32_268361729(r + i, & zetas_inv_asm[zeta_i]);
    }

    for (i = 0; i < 960*4; i += 32) {
        if (i % 512 >= 256) continue;

        zeta_i = (1024+64+32+16+8+4)*4 + (i >> 9);
        invntt_level7_avx_s32_268361729(r + i, & zetas_inv_asm[zeta_i]);
    }

    for (i = 0; i < 896*4; i += 32) {
        if (i % 1024 >= 512) continue;

        zeta_i = (1024+64+32+16+8+4+2)*4 + (i >> 10);
        invntt_level8_avx_s32_268361729(r + i, & zetas_inv_asm[zeta_i]);
    }

    for (i = 0; i < 768*4; i += 32) {
        if (i % 2048 >= 1024) continue;

        zeta_i = (1024+64+32+16+8+4+2+1)*4 + (i >> 11);
        invntt_level9_avx_s32_268361729(r + i, & zetas_inv_asm[zeta_i]);
    }
    
    for (i = 0; i < 512*4; i += 32) invntt_level10_avx_s32_268361729(r + i, & zetas_inv_asm[4606]);
    return;
}

void inv_ntt_avx_268271617(int32_t * r,
    const int32_t * zetas_inv_asm) {
    int zeta_i, i;

    for (i = 0; i < 1024*4; i += 64) {
        zeta_i = 32 * (i >> 6);
        invntt_level0_avx_s32_268271617(r + i, & zetas_inv_asm[zeta_i]);
    }

    for (i = 0; i < 1024*4; i += 64) {
        zeta_i = 1024*2 + 32 * (i >> 6);
        invntt_level1_avx_s32_268271617(r + i, & zetas_inv_asm[zeta_i]);
    }

    for (i = 0; i < 1024*4; i += 64) {
        zeta_i = 1024*4 + 4 * (i >> 6);
        invntt_level2_avx_s32_268271617(r + i, & zetas_inv_asm[zeta_i]);
    }
    for (i = 0; i < 1024*4; i += 64) {
        zeta_i = (1024+64)*4 + 2 * (i >> 6);
        invntt_level3_avx_s32_268271617(r + i, & zetas_inv_asm[zeta_i]);
    }
    for (i = 0; i < 1016*4; i += 32) {
        if (i % 64 >= 32) continue;

        zeta_i = (1024+64+32)*4 + (i >> 6);
        invntt_level4_avx_s32_268271617(r + i, & zetas_inv_asm[zeta_i]);
    }

    for (i = 0; i < 1008*4; i += 32) {
        if (i % 128 >= 64) continue;

        zeta_i = (1024+64+32+16)*4 + (i >> 7);
        invntt_level5_avx_s32_268271617(r + i, & zetas_inv_asm[zeta_i]);
    }

    for (i = 0; i < 992*4; i += 32) {
        if (i % 256 >= 128) continue;

        zeta_i = (1024+64+32+16+8)*4 + (i >> 8);
        invntt_level6_avx_s32_268271617(r + i, & zetas_inv_asm[zeta_i]);
    }

    for (i = 0; i < 960*4; i += 32) {
        if (i % 512 >= 256) continue;

        zeta_i = (1024+64+32+16+8+4)*4 + (i >> 9);
        invntt_level7_avx_s32_268271617(r + i, & zetas_inv_asm[zeta_i]);
    }

    for (i = 0; i < 896*4; i += 32) {
        if (i % 1024 >= 512) continue;

        zeta_i = (1024+64+32+16+8+4+2)*4 + (i >> 10);
        invntt_level8_avx_s32_268271617(r + i, & zetas_inv_asm[zeta_i]);
    }

    for (i = 0; i < 768*4; i += 32) {
        if (i % 2048 >= 1024) continue;

        zeta_i = (1024+64+32+16+8+4+2+1)*4 + (i >> 11);
        invntt_level9_avx_s32_268271617(r + i, & zetas_inv_asm[zeta_i]);
    }
    
    for (i = 0; i < 512*4; i += 32) invntt_level10_avx_s32_268271617(r + i, & zetas_inv_asm[4606]);
    return;
}

void inv_ntt_avx_268238849(int32_t * r,
    const int32_t * zetas_inv_asm) {
    int zeta_i, i;

    for (i = 0; i < 1024*4; i += 64) {
        zeta_i = 32 * (i >> 6);
        invntt_level0_avx_s32_268238849(r + i, & zetas_inv_asm[zeta_i]);
    }

    for (i = 0; i < 1024*4; i += 64) {
        zeta_i = 1024*2 + 32 * (i >> 6);
        invntt_level1_avx_s32_268238849(r + i, & zetas_inv_asm[zeta_i]);
    }

    for (i = 0; i < 1024*4; i += 64) {
        zeta_i = 1024*4 + 4 * (i >> 6);
        invntt_level2_avx_s32_268238849(r + i, & zetas_inv_asm[zeta_i]);
    }
    for (i = 0; i < 1024*4; i += 64) {
        zeta_i = (1024+64)*4 + 2 * (i >> 6);
        invntt_level3_avx_s32_268238849(r + i, & zetas_inv_asm[zeta_i]);
    }
    for (i = 0; i < 1016*4; i += 32) {
        if (i % 64 >= 32) continue;

        zeta_i = (1024+64+32)*4 + (i >> 6);
        invntt_level4_avx_s32_268238849(r + i, & zetas_inv_asm[zeta_i]);
    }

    for (i = 0; i < 1008*4; i += 32) {
        if (i % 128 >= 64) continue;

        zeta_i = (1024+64+32+16)*4 + (i >> 7);
        invntt_level5_avx_s32_268238849(r + i, & zetas_inv_asm[zeta_i]);
    }

    for (i = 0; i < 992*4; i += 32) {
        if (i % 256 >= 128) continue;

        zeta_i = (1024+64+32+16+8)*4 + (i >> 8);
        invntt_level6_avx_s32_268238849(r + i, & zetas_inv_asm[zeta_i]);
    }

    for (i = 0; i < 960*4; i += 32) {
        if (i % 512 >= 256) continue;

        zeta_i = (1024+64+32+16+8+4)*4 + (i >> 9);
        invntt_level7_avx_s32_268238849(r + i, & zetas_inv_asm[zeta_i]);
    }

    for (i = 0; i < 896*4; i += 32) {
        if (i % 1024 >= 512) continue;

        zeta_i = (1024+64+32+16+8+4+2)*4 + (i >> 10);
        invntt_level8_avx_s32_268238849(r + i, & zetas_inv_asm[zeta_i]);
    }

    for (i = 0; i < 768*4; i += 32) {
        if (i % 2048 >= 1024) continue;

        zeta_i = (1024+64+32+16+8+4+2+1)*4 + (i >> 11);
        invntt_level9_avx_s32_268238849(r + i, & zetas_inv_asm[zeta_i]);
    }
    
    for (i = 0; i < 512*4; i += 32) invntt_level10_avx_s32_268238849(r + i, & zetas_inv_asm[4606]);
    return;
}