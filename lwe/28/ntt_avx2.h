#ifndef NTT_H
#define NTT_H

#include <stdint.h>

void ntt_level0_avx(int16_t *r, const uint16_t *zetas);
void ntt_level0_avx_s32(int32_t *r, const int32_t *zetas);
void ntt_level1_avx_s32(int32_t *r, const int32_t *zetas);
void ntt_level2_avx_s32(int32_t *r, const int32_t *zetas);
void ntt_level3_avx_s32(int32_t *r, const int32_t *zetas);
void ntt_level4_avx_s32(int32_t *r, const int32_t *zetas);
void ntt_level5_avx_s32(int32_t *r, const int32_t *zetas);
void ntt_level6_avx_s32(int32_t *r, const int32_t *zetas);
void ntt_level7_avx_s32(int32_t *r, const int32_t *zetas);
void ntt_level8_avx_s32(int32_t *r, const int32_t *zetas);

void invntt_level0_avx_s32(int32_t *r, const int32_t *zetas);
void invntt_level1_avx_s32(int32_t *r, const int32_t *zetas);
void invntt_level2_avx_s32(int32_t *r, const int32_t *zetas);
void invntt_level3_avx_s32(int32_t *r, const int32_t *zetas);
void invntt_level4_avx_s32(int32_t *r, const int32_t *zetas);
void invntt_level5_avx_s32(int32_t *r, const int32_t *zetas);
void invntt_level6_avx_s32(int32_t *r, const int32_t *zetas);
void invntt_level7_avx_s32(int32_t *r, const int32_t *zetas);

void invntt_level8_avx_s32(int32_t *r, const int32_t *zetas);

void invntt_level_final_avx_s32(int32_t *r);

void shuffle_test(int32_t *r);

#endif
