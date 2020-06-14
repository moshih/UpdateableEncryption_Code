#ifndef NTT_H
#define NTT_H

#include <stdint.h>

void invntt_level0_avx_s32_268369921(int32_t *r, const int32_t *zetas);
void invntt_level1_avx_s32_268369921(int32_t *r, const int32_t *zetas);
void invntt_level2_avx_s32_268369921(int32_t *r, const int32_t *zetas);
void invntt_level3_avx_s32_268369921(int32_t *r, const int32_t *zetas);
void invntt_level4_avx_s32_268369921(int32_t *r, const int32_t *zetas);
void invntt_level5_avx_s32_268369921(int32_t *r, const int32_t *zetas);
void invntt_level6_avx_s32_268369921(int32_t *r, const int32_t *zetas);
void invntt_level7_avx_s32_268369921(int32_t *r, const int32_t *zetas);
void invntt_level8_avx_s32_268369921(int32_t *r, const int32_t *zetas);
void invntt_level9_avx_s32_268369921(int32_t *r, const int32_t *zetas);

void invntt_level10_avx_s32_268369921(int32_t *r, const int32_t *zetas);

void invntt_level_final_avx_s32_268369921(int32_t *r);

void invntt_level0_avx_s32_268361729(int32_t *r, const int32_t *zetas);
void invntt_level1_avx_s32_268361729(int32_t *r, const int32_t *zetas);
void invntt_level2_avx_s32_268361729(int32_t *r, const int32_t *zetas);
void invntt_level3_avx_s32_268361729(int32_t *r, const int32_t *zetas);
void invntt_level4_avx_s32_268361729(int32_t *r, const int32_t *zetas);
void invntt_level5_avx_s32_268361729(int32_t *r, const int32_t *zetas);
void invntt_level6_avx_s32_268361729(int32_t *r, const int32_t *zetas);
void invntt_level7_avx_s32_268361729(int32_t *r, const int32_t *zetas);
void invntt_level8_avx_s32_268361729(int32_t *r, const int32_t *zetas);
void invntt_level9_avx_s32_268361729(int32_t *r, const int32_t *zetas);

void invntt_level10_avx_s32_268361729(int32_t *r, const int32_t *zetas);

void invntt_level_final_avx_s32_268361729(int32_t *r);

void invntt_level0_avx_s32_268271617(int32_t *r, const int32_t *zetas);
void invntt_level1_avx_s32_268271617(int32_t *r, const int32_t *zetas);
void invntt_level2_avx_s32_268271617(int32_t *r, const int32_t *zetas);
void invntt_level3_avx_s32_268271617(int32_t *r, const int32_t *zetas);
void invntt_level4_avx_s32_268271617(int32_t *r, const int32_t *zetas);
void invntt_level5_avx_s32_268271617(int32_t *r, const int32_t *zetas);
void invntt_level6_avx_s32_268271617(int32_t *r, const int32_t *zetas);
void invntt_level7_avx_s32_268271617(int32_t *r, const int32_t *zetas);
void invntt_level8_avx_s32_268271617(int32_t *r, const int32_t *zetas);
void invntt_level9_avx_s32_268271617(int32_t *r, const int32_t *zetas);

void invntt_level10_avx_s32_268271617(int32_t *r, const int32_t *zetas);

void invntt_level_final_avx_s32_268271617(int32_t *r);

void shuffle_test(int32_t *r);

#endif
