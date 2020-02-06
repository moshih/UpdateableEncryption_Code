#include <stdio.h>
#include <stdint.h>

#include "ntt_avx2.h"

void inv_ntt_avx(int32_t *r, const int32_t *zetas_inv_asm);
void ntt_avx(int32_t *r, const int32_t *zetas_asm);