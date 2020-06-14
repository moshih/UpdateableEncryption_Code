.macro shuffle8 r0,r1,r2,r3
vperm2i128	$0x20,%ymm\r1,%ymm\r0,%ymm\r2
vperm2i128	$0x31,%ymm\r1,%ymm\r0,%ymm\r3
.endm

.macro shuffle4 r0,r1,r2,r3
vpunpcklqdq	%ymm\r1,%ymm\r0,%ymm\r2
vpunpckhqdq	%ymm\r1,%ymm\r0,%ymm\r3
.endm

.macro shuffle2 r0,r1,r2,r3
vpsllq		$32,%ymm\r1,%ymm12
vpsrlq		$32,%ymm\r0,%ymm13
vpblendd	$0xAA,%ymm12,%ymm\r0,%ymm\r2
vpblendd	$0xAA,%ymm\r1,%ymm13,%ymm\r3
.endm

.macro shuffle1 r0,r1,r2,r3
vpslld		$16,%ymm\r1,%ymm12
vpsrld		$16,%ymm\r0,%ymm13
vpblendw	$0xAA,%ymm12,%ymm\r0,%ymm\r2
vpblendw	$0xAA,%ymm\r1,%ymm13,%ymm\r3
.endm

######################
# barrett reduce
.macro barrett_reduce_32 i0,o0 br0=14
vpmuldq 		%ymm\i0,%ymm\br0,%ymm12
vpsrlq          $32,%ymm\i0,%ymm11
vpmuldq 		%ymm11,%ymm\br0,%ymm11
# product high is 11
vshufps         $1+4+8+16+64+128,  %ymm11, %ymm12,%ymm13
vpshufd         $216, %ymm13, %ymm11

vpsrad          $26,%ymm11,%ymm11
vpmulld			%ymm0,%ymm11,%ymm11
vpsubd			 %ymm11,%ymm\i0, %ymm\o0
.endm
#vmovdqa		%ymm13,%ymm3
######################

.macro butterfly_32 rl0,rl1,rl2,rl3,rh0,rh1,rh2,rh3 zl0=15,zl1=15,zh0=1,zh1=1

vpmuldq 		%ymm\rh0,%ymm\zl0,%ymm12
vpsrlq          $32,%ymm\rh0,%ymm10
vpsrlq          $32,%ymm\zl0,%ymm11
vpmuldq 		%ymm10,%ymm11,%ymm11
vshufps         $8+128,%ymm11,  %ymm12, %ymm10

# product low is ymm10
vpshufd         $216, %ymm10, %ymm10

# product high is 12
vshufps         $1+4+8+16+64+128,  %ymm11, %ymm12,%ymm13
vpshufd         $216, %ymm13, %ymm11

vpmulld         %ymm10,%ymm1,%ymm10
vpmuldq 		%ymm10,%ymm0,%ymm12

vpsrlq          $32,%ymm10,%ymm10
vpmuldq 		%ymm10,%ymm0,%ymm13
vshufps         $1+4+8+16+64+128, %ymm13, %ymm12, %ymm10
vpshufd         $216, %ymm10, %ymm10
vpsubd          %ymm10, %ymm11, %ymm10
vpsubd			%ymm10, %ymm\rl0, %ymm\rh0
vpaddd			%ymm10, %ymm\rl0, %ymm\rl0

########################################################################
vpmuldq 		%ymm\rh1,%ymm\zl0,%ymm12
vpsrlq          $32,%ymm\rh1,%ymm10
vpsrlq          $32,%ymm\zl0,%ymm11
vpmuldq 		%ymm10,%ymm11,%ymm11
vshufps         $8+128,%ymm11,  %ymm12, %ymm10

# product low is ymm10
vpshufd         $216, %ymm10, %ymm10

# product high is 12
vshufps         $1+4+8+16+64+128,  %ymm11, %ymm12,%ymm13
vpshufd         $216, %ymm13, %ymm11

vpmulld         %ymm10,%ymm1,%ymm10
vpmuldq 		%ymm10,%ymm0,%ymm12

vpsrlq          $32,%ymm10,%ymm10
vpmuldq 		%ymm10,%ymm0,%ymm13
vshufps         $1+4+8+16+64+128, %ymm13, %ymm12, %ymm10
vpshufd         $216, %ymm10, %ymm10
vpsubd          %ymm10, %ymm11, %ymm10
vpsubd			%ymm10, %ymm\rl1, %ymm\rh1
vpaddd			%ymm10, %ymm\rl1, %ymm\rl1
########################################################################
vpmuldq 		%ymm\rh2,%ymm\zl0,%ymm12
vpsrlq          $32,%ymm\rh2,%ymm10
vpsrlq          $32,%ymm\zl0,%ymm11
vpmuldq 		%ymm10,%ymm11,%ymm11
vshufps         $8+128,%ymm11,  %ymm12, %ymm10

# product low is ymm10
vpshufd         $216, %ymm10, %ymm10

# product high is 12
vshufps         $1+4+8+16+64+128,  %ymm11, %ymm12,%ymm13
vpshufd         $216, %ymm13, %ymm11

vpmulld         %ymm10,%ymm1,%ymm10
vpmuldq 		%ymm10,%ymm0,%ymm12

vpsrlq          $32,%ymm10,%ymm10
vpmuldq 		%ymm10,%ymm0,%ymm13
vshufps         $1+4+8+16+64+128, %ymm13, %ymm12, %ymm10
vpshufd         $216, %ymm10, %ymm10
vpsubd          %ymm10, %ymm11, %ymm10
vpsubd			%ymm10, %ymm\rl2, %ymm\rh2
vpaddd			%ymm10, %ymm\rl2, %ymm\rl2
########################################################################
vpmuldq 		%ymm\rh3,%ymm\zl0,%ymm12
vpsrlq          $32,%ymm\rh3,%ymm10
vpsrlq          $32,%ymm\zl0,%ymm11
vpmuldq 		%ymm10,%ymm11,%ymm11
vshufps         $8+128,%ymm11,  %ymm12, %ymm10

# product low is ymm10
vpshufd         $216, %ymm10, %ymm10

# product high is 12
vshufps         $1+4+8+16+64+128,  %ymm11, %ymm12,%ymm13
vpshufd         $216, %ymm13, %ymm11

vpmulld         %ymm10,%ymm1,%ymm10
vpmuldq 		%ymm10,%ymm0,%ymm12

vpsrlq          $32,%ymm10,%ymm10
vpmuldq 		%ymm10,%ymm0,%ymm13
vshufps         $1+4+8+16+64+128, %ymm13, %ymm12, %ymm10
vpshufd         $216, %ymm10, %ymm10
vpsubd          %ymm10, %ymm11, %ymm10
vpsubd			%ymm10, %ymm\rl3, %ymm\rh3
vpaddd			%ymm10, %ymm\rl3, %ymm\rl3
.endm

.macro butterfly_32_uniform_zeta rl0,rl1,rl2,rl3,rh0,rh1,rh2,rh3 zl0=15,zl1=15,zh0=1,zh1=1

vpmuldq 		%ymm\rh0,%ymm\zl0,%ymm12
vpsrlq          $32,%ymm\rh0,%ymm10
vpmuldq 		%ymm10,%ymm\zl0,%ymm11
vshufps         $8+128,%ymm11,  %ymm12, %ymm10

# product low is ymm10
vpshufd         $216, %ymm10, %ymm10

# product high is 12
vshufps         $1+4+8+16+64+128,  %ymm11, %ymm12,%ymm13
vpshufd         $216, %ymm13, %ymm11

vpmulld         %ymm10,%ymm1,%ymm10
vpmuldq 		%ymm10,%ymm0,%ymm12

vpsrlq          $32,%ymm10,%ymm10
vpmuldq 		%ymm10,%ymm0,%ymm13
vshufps         $1+4+8+16+64+128, %ymm13, %ymm12, %ymm10
vpshufd         $216, %ymm10, %ymm10
vpsubd          %ymm10, %ymm11, %ymm10
vpsubd			%ymm10, %ymm\rl0, %ymm\rh0
vpaddd			%ymm10, %ymm\rl0, %ymm\rl0

########################################################################
vpmuldq 		%ymm\rh1,%ymm\zl0,%ymm12
vpsrlq          $32,%ymm\rh1,%ymm10
#vpsrlq          $32,%ymm\zl0,%ymm11
vpmuldq 		%ymm10,%ymm\zl0,%ymm11
vshufps         $8+128,%ymm11,  %ymm12, %ymm10

# product low is ymm10
vpshufd         $216, %ymm10, %ymm10

# product high is 12
vshufps         $1+4+8+16+64+128,  %ymm11, %ymm12,%ymm13
vpshufd         $216, %ymm13, %ymm11

vpmulld         %ymm10,%ymm1,%ymm10
vpmuldq 		%ymm10,%ymm0,%ymm12

vpsrlq          $32,%ymm10,%ymm10
vpmuldq 		%ymm10,%ymm0,%ymm13
vshufps         $1+4+8+16+64+128, %ymm13, %ymm12, %ymm10
vpshufd         $216, %ymm10, %ymm10
vpsubd          %ymm10, %ymm11, %ymm10
vpsubd			%ymm10, %ymm\rl1, %ymm\rh1
vpaddd			%ymm10, %ymm\rl1, %ymm\rl1
########################################################################
vpmuldq 		%ymm\rh2,%ymm\zl0,%ymm12
vpsrlq          $32,%ymm\rh2,%ymm10
#vpsrlq          $32,%ymm\zl0,%ymm11
vpmuldq 		%ymm10,%ymm\zl0,%ymm11
vshufps         $8+128,%ymm11,  %ymm12, %ymm10

# product low is ymm10
vpshufd         $216, %ymm10, %ymm10

# product high is 12
vshufps         $1+4+8+16+64+128,  %ymm11, %ymm12,%ymm13
vpshufd         $216, %ymm13, %ymm11

vpmulld         %ymm10,%ymm1,%ymm10
vpmuldq 		%ymm10,%ymm0,%ymm12

vpsrlq          $32,%ymm10,%ymm10
vpmuldq 		%ymm10,%ymm0,%ymm13
vshufps         $1+4+8+16+64+128, %ymm13, %ymm12, %ymm10
vpshufd         $216, %ymm10, %ymm10
vpsubd          %ymm10, %ymm11, %ymm10
vpsubd			%ymm10, %ymm\rl2, %ymm\rh2
vpaddd			%ymm10, %ymm\rl2, %ymm\rl2
########################################################################
vpmuldq 		%ymm\rh3,%ymm\zl0,%ymm12
vpsrlq          $32,%ymm\rh3,%ymm10
#vpsrlq          $32,%ymm\zl0,%ymm11
vpmuldq 		%ymm10,%ymm\zl0,%ymm11
vshufps         $8+128,%ymm11,  %ymm12, %ymm10

# product low is ymm10
vpshufd         $216, %ymm10, %ymm10

# product high is 12
vshufps         $1+4+8+16+64+128,  %ymm11, %ymm12,%ymm13
vpshufd         $216, %ymm13, %ymm11

vpmulld         %ymm10,%ymm1,%ymm10
vpmuldq 		%ymm10,%ymm0,%ymm12

vpsrlq          $32,%ymm10,%ymm10
vpmuldq 		%ymm10,%ymm0,%ymm13
vshufps         $1+4+8+16+64+128, %ymm13, %ymm12, %ymm10
vpshufd         $216, %ymm10, %ymm10
vpsubd          %ymm10, %ymm11, %ymm10
vpsubd			%ymm10, %ymm\rl3, %ymm\rh3
vpaddd			%ymm10, %ymm\rl3, %ymm\rl3
.endm

.macro butterfly_32_uniform_zeta_double rl0,rl1,rh0,rh1 zl0=15,zl1=15,zh0=1,zh1=1

vpmuldq 		%ymm\rh0,%ymm\zl0,%ymm12
vpsrlq          $32,%ymm\rh0,%ymm10
#vpsrlq          $32,%ymm\zl0,%ymm11
vpmuldq 		%ymm10,%ymm\zl0,%ymm11
vshufps         $8+128,%ymm11,  %ymm12, %ymm10

# product low is ymm10
vpshufd         $216, %ymm10, %ymm10

# product high is 12
vshufps         $1+4+8+16+64+128,  %ymm11, %ymm12,%ymm13
vpshufd         $216, %ymm13, %ymm11

vpmulld         %ymm10,%ymm1,%ymm10
vpmuldq 		%ymm10,%ymm0,%ymm12

vpsrlq          $32,%ymm10,%ymm10
vpmuldq 		%ymm10,%ymm0,%ymm13
vshufps         $1+4+8+16+64+128, %ymm13, %ymm12, %ymm10
vpshufd         $216, %ymm10, %ymm10
vpsubd          %ymm10, %ymm11, %ymm10
vpsubd			%ymm10, %ymm\rl0, %ymm\rh0
vpaddd			%ymm10, %ymm\rl0, %ymm\rl0

########################################################################
vpmuldq 		%ymm\rh1,%ymm\zl0,%ymm12
vpsrlq          $32,%ymm\rh1,%ymm10
#vpsrlq          $32,%ymm\zl0,%ymm11
vpmuldq 		%ymm10,%ymm\zl0,%ymm11
vshufps         $8+128,%ymm11,  %ymm12, %ymm10

# product low is ymm10
vpshufd         $216, %ymm10, %ymm10

# product high is 12
vshufps         $1+4+8+16+64+128,  %ymm11, %ymm12,%ymm13
vpshufd         $216, %ymm13, %ymm11

vpmulld         %ymm10,%ymm1,%ymm10
vpmuldq 		%ymm10,%ymm0,%ymm12

vpsrlq          $32,%ymm10,%ymm10
vpmuldq 		%ymm10,%ymm0,%ymm13
vshufps         $1+4+8+16+64+128, %ymm13, %ymm12, %ymm10
vpshufd         $216, %ymm10, %ymm10
vpsubd          %ymm10, %ymm11, %ymm10
vpsubd			%ymm10, %ymm\rl1, %ymm\rh1
vpaddd			%ymm10, %ymm\rl1, %ymm\rl1
.endm

.macro butterfly_32_uniform_zeta_quarter rl0,rl1 zl0=15,zl1=15,zh0=1,zh1=1

shuffle4 \rl0,\rl1,14,\rl0

vpmuldq 		%ymm\rl0,%ymm\zl0,%ymm12
vpsrlq          $32,%ymm\rl0,%ymm10
#vpsrlq          $32,%ymm\zl0,%ymm11
vpmuldq 		%ymm10,%ymm\zl0,%ymm11
vshufps         $8+128,%ymm11,  %ymm12, %ymm10

# product low is ymm10
vpshufd         $216, %ymm10, %ymm10

# product high is 12
vshufps         $1+4+8+16+64+128,  %ymm11, %ymm12,%ymm13
vpshufd         $216, %ymm13, %ymm11

vpmulld         %ymm10,%ymm1,%ymm10
vpmuldq 		%ymm10,%ymm0,%ymm12

vpsrlq          $32,%ymm10,%ymm10
vpmuldq 		%ymm10,%ymm0,%ymm13
vshufps         $1+4+8+16+64+128, %ymm13, %ymm12, %ymm10
vpshufd         $216, %ymm10, %ymm10
vpsubd          %ymm10, %ymm11, %ymm10

vpsubd			%ymm10, %ymm14, %ymm\rl1
vpaddd			%ymm10, %ymm14, %ymm14

shuffle4 14,\rl1,\rl0,\rl1

.endm

.macro fqmul_32_uniform_zeta_quarter rl0,rl1
shuffle4 \rl0,\rl1,13,\rl0
vmovdqa   %ymm13,%ymm\rl1

vpaddd    %ymm\rl1, %ymm\rl0, %ymm10
barrett_reduce_32 10 10
vpsubd     %ymm\rl0,%ymm\rl1,%ymm\rl1
vmovdqa   %ymm10,%ymm\rl0
fqmul_32_uniform_zeta_subroutine \rl1,\rl1
vmovdqa   %ymm\rl0,%ymm10
#input are 14 and \rl0
#vmovdqa   %ymm\rl1,%ymm14
shuffle4 10,\rl1,\rl0,\rl1
.endm

.macro fqmul_32_uniform_zeta_half rl0,rl1
shuffle8 \rl0,\rl1,13,\rl0
vmovdqa   %ymm13,%ymm\rl1

vpaddd    %ymm\rl1, %ymm\rl0, %ymm10
barrett_reduce_32 10 10
vpsubd     %ymm\rl0,%ymm\rl1,%ymm\rl1
vmovdqa   %ymm10,%ymm\rl0
fqmul_32_uniform_zeta_subroutine \rl1,\rl1
vmovdqa   %ymm\rl0,%ymm10
shuffle8 10,\rl1,\rl0,\rl1
.endm

.macro fqmul_32_uniform_zeta_single rl0,rl1

vpaddd    %ymm\rl0, %ymm\rl1, %ymm10
barrett_reduce_32 10,10
vpsubd     %ymm\rl1,%ymm\rl0,%ymm\rl1
vmovdqa   %ymm10,%ymm\rl0
fqmul_32_uniform_zeta_subroutine \rl1,\rl1
.endm

.macro butterfly_32_uniform_zeta_half rl0,rl1 zl0=15,zl1=15,zh0=1,zh1=1

shuffle8 \rl0,\rl1,14,\rl0

vpmuldq 		%ymm\rl0,%ymm\zl0,%ymm12
vpsrlq          $32,%ymm\rl0,%ymm10
vpmuldq 		%ymm10,%ymm\zl0,%ymm11
vshufps         $8+128,%ymm11,  %ymm12, %ymm10

# product low is ymm10
vpshufd         $216, %ymm10, %ymm10

# product high is 12
vshufps         $1+4+8+16+64+128,  %ymm11, %ymm12,%ymm13
vpshufd         $216, %ymm13, %ymm11

vpmulld         %ymm10,%ymm1,%ymm10
vpmuldq 		%ymm10,%ymm0,%ymm12

vpsrlq          $32,%ymm10,%ymm10
vpmuldq 		%ymm10,%ymm0,%ymm13
vshufps         $1+4+8+16+64+128, %ymm13, %ymm12, %ymm10
vpshufd         $216, %ymm10, %ymm10
vpsubd          %ymm10, %ymm11, %ymm10

vpsubd			%ymm10, %ymm14, %ymm\rl1
vpaddd			%ymm10, %ymm14, %ymm14

shuffle8 14,\rl1,\rl0,\rl1

.endm


.macro fqmul_32_uniform_zeta_subroutine rl0,rl1 zl0=15,zl1=15,zh0=1,zh1=1
vpmuldq 		%ymm\rl0,%ymm\zl0,%ymm12
vpsrlq          $32,%ymm\rl0,%ymm10
#vpsrlq          $32,%ymm\zl0,%ymm11
vpmuldq 		%ymm10,%ymm\zl0,%ymm11
vshufps         $8+128,%ymm11,  %ymm12, %ymm10

# product low is ymm10
vpshufd         $216, %ymm10, %ymm10

# product high is 12
vshufps         $1+4+8+16+64+128,  %ymm11, %ymm12,%ymm13
vpshufd         $216, %ymm13, %ymm11

vpmulld         %ymm10,%ymm1,%ymm10
vpmuldq 		%ymm10,%ymm0,%ymm12

vpsrlq          $32,%ymm10,%ymm10
vpmuldq 		%ymm10,%ymm0,%ymm13
vshufps         $1+4+8+16+64+128, %ymm13, %ymm12, %ymm10
vpshufd         $216, %ymm10, %ymm10
vpsubd          %ymm10, %ymm11, %ymm\rl1
.endm

.macro fqmul_32_uniform_zeta rl0,rl1,rl2,rl3,rh0,rh1,rh2,rh3 zl0=15,zl1=15,zh0=1,zh1=1

vpmuldq 		%ymm\rl0,%ymm\zl0,%ymm12
vpsrlq          $32,%ymm\rl0,%ymm10
vpmuldq 		%ymm10,%ymm\zl0,%ymm11
vshufps         $8+128,%ymm11,  %ymm12, %ymm10
# product low is ymm10
vpshufd         $216, %ymm10, %ymm10
# product high is 12
vshufps         $1+4+8+16+64+128,  %ymm11, %ymm12,%ymm13
vpshufd         $216, %ymm13, %ymm11

vpmulld         %ymm10,%ymm1,%ymm10
vpmuldq 		%ymm10,%ymm0,%ymm12
vpsrlq          $32,%ymm10,%ymm10
vpmuldq 		%ymm10,%ymm0,%ymm13
vshufps         $1+4+8+16+64+128, %ymm13, %ymm12, %ymm10
vpshufd         $216, %ymm10, %ymm10
vpsubd          %ymm10, %ymm11, %ymm\rh0

###################################################################
vpmuldq 		%ymm\rl1,%ymm\zl0,%ymm12
vpsrlq          $32,%ymm\rl1,%ymm10
vpmuldq 		%ymm10,%ymm\zl0,%ymm11
vshufps         $8+128,%ymm11,  %ymm12, %ymm10
# product low is ymm10
vpshufd         $216, %ymm10, %ymm10
# product high is 12
vshufps         $1+4+8+16+64+128,  %ymm11, %ymm12,%ymm13
vpshufd         $216, %ymm13, %ymm11

vpmulld         %ymm10,%ymm1,%ymm10
vpmuldq 		%ymm10,%ymm0,%ymm12
vpsrlq          $32,%ymm10,%ymm10
vpmuldq 		%ymm10,%ymm0,%ymm13
vshufps         $1+4+8+16+64+128, %ymm13, %ymm12, %ymm10
vpshufd         $216, %ymm10, %ymm10
vpsubd          %ymm10, %ymm11, %ymm\rh1

###################################################################
vpmuldq 		%ymm\rl2,%ymm\zl0,%ymm12
vpsrlq          $32,%ymm\rl2,%ymm10
vpmuldq 		%ymm10,%ymm\zl0,%ymm11
vshufps         $8+128,%ymm11,  %ymm12, %ymm10
# product low is ymm10
vpshufd         $216, %ymm10, %ymm10
# product high is 12
vshufps         $1+4+8+16+64+128,  %ymm11, %ymm12,%ymm13
vpshufd         $216, %ymm13, %ymm11

vpmulld         %ymm10,%ymm1,%ymm10
vpmuldq 		%ymm10,%ymm0,%ymm12
vpsrlq          $32,%ymm10,%ymm10
vpmuldq 		%ymm10,%ymm0,%ymm13
vshufps         $1+4+8+16+64+128, %ymm13, %ymm12, %ymm10
vpshufd         $216, %ymm10, %ymm10
vpsubd          %ymm10, %ymm11, %ymm\rh2

###################################################################
vpmuldq 		%ymm\rl3,%ymm\zl0,%ymm12
vpsrlq          $32,%ymm\rl3,%ymm10
vpmuldq 		%ymm10,%ymm\zl0,%ymm11
vshufps         $8+128,%ymm11,  %ymm12, %ymm10
# product low is ymm10
vpshufd         $216, %ymm10, %ymm10
# product high is 12
vshufps         $1+4+8+16+64+128,  %ymm11, %ymm12,%ymm13
vpshufd         $216, %ymm13, %ymm11

vpmulld         %ymm10,%ymm1,%ymm10
vpmuldq 		%ymm10,%ymm0,%ymm12
vpsrlq          $32,%ymm10,%ymm10
vpmuldq 		%ymm10,%ymm0,%ymm13
vshufps         $1+4+8+16+64+128, %ymm13, %ymm12, %ymm10
vpshufd         $216, %ymm10, %ymm10
vpsubd          %ymm10, %ymm11, %ymm\rh3

.endm

.macro butterfly_32_uniform_zeta_single rl0,rh0 zl0=15,zl1=15,zh0=1,zh1=1

vpmuldq 		%ymm\rh0,%ymm\zl0,%ymm12
vpsrlq          $32,%ymm\rh0,%ymm10
vpmuldq 		%ymm10,%ymm\zl0,%ymm11
vshufps         $8+128,%ymm11,  %ymm12, %ymm10

# product low is ymm10
vpshufd         $216, %ymm10, %ymm10

# product high is 12
vshufps         $1+4+8+16+64+128,  %ymm11, %ymm12,%ymm13
vpshufd         $216, %ymm13, %ymm11

vpmulld         %ymm10,%ymm1,%ymm10
vpmuldq 		%ymm10,%ymm0,%ymm12

vpsrlq          $32,%ymm10,%ymm10
vpmuldq 		%ymm10,%ymm0,%ymm13
vshufps         $1+4+8+16+64+128, %ymm13, %ymm12, %ymm10
vpshufd         $216, %ymm10, %ymm10
vpsubd          %ymm10, %ymm11, %ymm10
vpsubd			%ymm10, %ymm\rl0, %ymm\rh0
vpaddd			%ymm10, %ymm\rl0, %ymm\rl0
.endm

.global ntt_level0_avx_s32_268238849
ntt_level0_avx_s32_268238849:
#consts
vmovdqa		_32xq_268238849(%rip),%ymm0
vmovdqa		_32xqinv_268238849(%rip),%ymm1

level0_s32:
#zetas
vpbroadcastd (%rsi),%ymm15

#load
vmovdqa		(%rdi),%ymm2
vmovdqa		32(%rdi),%ymm3
vmovdqa		64(%rdi),%ymm4
vmovdqa		96(%rdi),%ymm5
vmovdqa		4096(%rdi),%ymm6
vmovdqa		4128(%rdi),%ymm7
vmovdqa		4160(%rdi),%ymm8
vmovdqa		4192(%rdi),%ymm9


butterfly_32_uniform_zeta 2,3,4,5,6,7,8,9

#store
vmovdqa		%ymm2,(%rdi)
vmovdqa		%ymm3,32(%rdi)
vmovdqa		%ymm4,64(%rdi)
vmovdqa		%ymm5,96(%rdi)
vmovdqa		%ymm6,4096(%rdi)
vmovdqa		%ymm7,4128(%rdi)
vmovdqa		%ymm8,4160(%rdi)
vmovdqa		%ymm9,4192(%rdi)

ret

.global invntt_level8_avx_s32_268238849
invntt_level8_avx_s32_268238849:
#consts
vmovdqa     _32xq_268238849(%rip),%ymm0
vmovdqa     _32xqinv_268238849(%rip),%ymm1

ilevel8_s32:
#zetas
vpbroadcastd (%rsi),%ymm15

#barrett v
vmovdqa     _64xbarrettv_268238849(%rip),%ymm14

#load
vmovdqa     (%rdi),%ymm2
vmovdqa     32(%rdi),%ymm3
vmovdqa     64(%rdi),%ymm4
vmovdqa     96(%rdi),%ymm5
vmovdqa     2048(%rdi),%ymm6
vmovdqa     2080(%rdi),%ymm7
vmovdqa     2112(%rdi),%ymm8
vmovdqa     2144(%rdi),%ymm9

fqmul_32_uniform_zeta_single  2,6
fqmul_32_uniform_zeta_single  3,7
fqmul_32_uniform_zeta_single  4,8
fqmul_32_uniform_zeta_single  5,9

#store
vmovdqa     %ymm2,(%rdi)
vmovdqa     %ymm3,32(%rdi)
vmovdqa     %ymm4,64(%rdi)
vmovdqa     %ymm5,96(%rdi)
vmovdqa     %ymm6,2048(%rdi)
vmovdqa     %ymm7,2080(%rdi)
vmovdqa     %ymm8,2112(%rdi)
vmovdqa     %ymm9,2144(%rdi)
ret

.global invntt_level9_avx_s32_268238849
invntt_level9_avx_s32_268238849:
#consts
vmovdqa     _32xq_268238849(%rip),%ymm0
vmovdqa     _32xqinv_268238849(%rip),%ymm1

ilevel9_s32:
#zetas
vpbroadcastd (%rsi),%ymm15

#barrett v
vmovdqa     _64xbarrettv_268238849(%rip),%ymm14

#load
vmovdqa     (%rdi),%ymm2
vmovdqa     32(%rdi),%ymm3
vmovdqa     64(%rdi),%ymm4
vmovdqa     96(%rdi),%ymm5
vmovdqa     4096(%rdi),%ymm6
vmovdqa     4128(%rdi),%ymm7
vmovdqa     4160(%rdi),%ymm8
vmovdqa     4192(%rdi),%ymm9

fqmul_32_uniform_zeta_single  2,6
fqmul_32_uniform_zeta_single  3,7
fqmul_32_uniform_zeta_single  4,8
fqmul_32_uniform_zeta_single  5,9

#store
vmovdqa     %ymm2,(%rdi)
vmovdqa     %ymm3,32(%rdi)
vmovdqa     %ymm4,64(%rdi)
vmovdqa     %ymm5,96(%rdi)
vmovdqa     %ymm6,4096(%rdi)
vmovdqa     %ymm7,4128(%rdi)
vmovdqa     %ymm8,4160(%rdi)
vmovdqa     %ymm9,4192(%rdi)
ret

.global invntt_level10_avx_s32_268238849
invntt_level10_avx_s32_268238849:
#consts
vmovdqa     _32xq_268238849(%rip),%ymm0
vmovdqa     _32xqinv_268238849(%rip),%ymm1

ilevel10_s32:
#zetas
vpbroadcastd (%rsi),%ymm15

#barrett v
vmovdqa     _64xbarrettv_268238849(%rip),%ymm14

#load
vmovdqa     (%rdi),%ymm2
vmovdqa     32(%rdi),%ymm3
vmovdqa     64(%rdi),%ymm4
vmovdqa     96(%rdi),%ymm5
vmovdqa     8192(%rdi),%ymm6
vmovdqa     8224(%rdi),%ymm7
vmovdqa     8256(%rdi),%ymm8
vmovdqa     8288(%rdi),%ymm9

fqmul_32_uniform_zeta_single  2,6
fqmul_32_uniform_zeta_single  3,7
fqmul_32_uniform_zeta_single  4,8
fqmul_32_uniform_zeta_single  5,9

vmovdqa     _32zeta_final_268238849(%rip),%ymm15
fqmul_32_uniform_zeta 2,3,4,5,2,3,4,5
fqmul_32_uniform_zeta 6,7,8,9,6,7,8,9

#store
vmovdqa     %ymm2,(%rdi)
vmovdqa     %ymm3,32(%rdi)
vmovdqa     %ymm4,64(%rdi)
vmovdqa     %ymm5,96(%rdi)
vmovdqa     %ymm6,8192(%rdi)
vmovdqa     %ymm7,8224(%rdi)
vmovdqa     %ymm8,8256(%rdi)
vmovdqa     %ymm9,8288(%rdi)
ret

.global invntt_level_final_avx_s32_268238849
invntt_level_final_avx_s32_268238849:
#consts
vmovdqa		_32xq_268238849(%rip),%ymm0
vmovdqa		_32xqinv_268238849(%rip),%ymm1

ilevelf_s32:
#zetas
vmovdqa		_32zeta_final_268238849(%rip),%ymm15

#load
vmovdqa		(%rdi),%ymm2
vmovdqa		32(%rdi),%ymm3
vmovdqa		64(%rdi),%ymm4
vmovdqa		96(%rdi),%ymm5
vmovdqa		128(%rdi),%ymm6
vmovdqa		160(%rdi),%ymm7
vmovdqa		192(%rdi),%ymm8
vmovdqa		224(%rdi),%ymm9

fqmul_32_uniform_zeta 2,3,4,5,2,3,4,5
fqmul_32_uniform_zeta 6,7,8,9,6,7,8,9

vmovdqa		%ymm2,(%rdi)
vmovdqa		%ymm3,32(%rdi)
vmovdqa		%ymm4,64(%rdi)
vmovdqa		%ymm5,96(%rdi)
vmovdqa		%ymm6,128(%rdi)
vmovdqa		%ymm7,160(%rdi)
vmovdqa		%ymm8,192(%rdi)
vmovdqa		%ymm9,224(%rdi)
ret

.global invntt_level0_avx_s32_268238849
invntt_level0_avx_s32_268238849:
#consts
vmovdqa		_32xq_268238849(%rip),%ymm0
vmovdqa		_32xqinv_268238849(%rip),%ymm1

ilevel0_s32:
#zetas
vmovdqu (%rsi),%ymm15

#barrett v
vmovdqa		_64xbarrettv_268238849(%rip),%ymm14

#load
vmovdqa		(%rdi),%ymm2
vmovdqa		32(%rdi),%ymm3
vmovdqa		64(%rdi),%ymm4
vmovdqa		96(%rdi),%ymm5
vmovdqa		128(%rdi),%ymm6
vmovdqa		160(%rdi),%ymm7
vmovdqa		192(%rdi),%ymm8
vmovdqa		224(%rdi),%ymm9

fqmul_32_uniform_zeta_quarter 2,3
vmovdqu 32(%rsi),%ymm15
fqmul_32_uniform_zeta_quarter 4,5
vmovdqu 64(%rsi),%ymm15
fqmul_32_uniform_zeta_quarter 6,7
vmovdqu 96(%rsi),%ymm15
fqmul_32_uniform_zeta_quarter 8,9

#store
vmovdqa		%ymm2,(%rdi)
vmovdqa		%ymm3,32(%rdi)
vmovdqa		%ymm4,64(%rdi)
vmovdqa		%ymm5,96(%rdi)
vmovdqa		%ymm6,128(%rdi)
vmovdqa		%ymm7,160(%rdi)
vmovdqa		%ymm8,192(%rdi)
vmovdqa		%ymm9,224(%rdi)
ret

.global ntt_level9_avx_s32_268238849
ntt_level9_avx_s32_268238849:
#consts
vmovdqa     _32xq_268238849(%rip),%ymm0
vmovdqa     _32xqinv_268238849(%rip),%ymm1

level9_s32:
#zetas
vmovdqu (%rsi),%ymm15

#load
vmovdqa     (%rdi),%ymm2
vmovdqa     32(%rdi),%ymm3
vmovdqa     64(%rdi),%ymm4
vmovdqa     96(%rdi),%ymm5
vmovdqa     128(%rdi),%ymm6
vmovdqa     160(%rdi),%ymm7
vmovdqa     192(%rdi),%ymm8
vmovdqa     224(%rdi),%ymm9

butterfly_32_uniform_zeta_quarter 2,3
vmovdqu 32(%rsi),%ymm15
butterfly_32_uniform_zeta_quarter 4,5
vmovdqu 64(%rsi),%ymm15
butterfly_32_uniform_zeta_quarter 6,7
vmovdqu 96(%rsi),%ymm15
butterfly_32_uniform_zeta_quarter 8,9

#store
vmovdqa     %ymm2,(%rdi)
vmovdqa     %ymm3,32(%rdi)
vmovdqa     %ymm4,64(%rdi)
vmovdqa     %ymm5,96(%rdi)
vmovdqa     %ymm6,128(%rdi)
vmovdqa     %ymm7,160(%rdi)
vmovdqa     %ymm8,192(%rdi)
vmovdqa     %ymm9,224(%rdi)
ret

.global ntt_level8_avx_s32_268238849
ntt_level8_avx_s32_268238849:
#consts
vmovdqa     _32xq_268238849(%rip),%ymm0
vmovdqa     _32xqinv_268238849(%rip),%ymm1

level8_s32:
#zetas
vmovdqu (%rsi),%ymm15

#load
vmovdqa     (%rdi),%ymm2
vmovdqa     32(%rdi),%ymm3
vmovdqa     64(%rdi),%ymm4
vmovdqa     96(%rdi),%ymm5
vmovdqa     128(%rdi),%ymm6
vmovdqa     160(%rdi),%ymm7
vmovdqa     192(%rdi),%ymm8
vmovdqa     224(%rdi),%ymm9

butterfly_32_uniform_zeta_half 2,3
vmovdqu 32(%rsi),%ymm15
butterfly_32_uniform_zeta_half 4,5
vmovdqu 64(%rsi),%ymm15
butterfly_32_uniform_zeta_half 6,7
vmovdqu 96(%rsi),%ymm15
butterfly_32_uniform_zeta_half 8,9

#store
vmovdqa     %ymm2,(%rdi)
vmovdqa     %ymm3,32(%rdi)
vmovdqa     %ymm4,64(%rdi)
vmovdqa     %ymm5,96(%rdi)
vmovdqa     %ymm6,128(%rdi)
vmovdqa     %ymm7,160(%rdi)
vmovdqa     %ymm8,192(%rdi)
vmovdqa     %ymm9,224(%rdi)
ret

.global invntt_level1_avx_s32_268238849
invntt_level1_avx_s32_268238849:
#consts
vmovdqa		_32xq_268238849(%rip),%ymm0
vmovdqa		_32xqinv_268238849(%rip),%ymm1

ilevel1_s32:
#zetas
vmovdqu (%rsi),%ymm15

#barrett v
vmovdqa		_64xbarrettv_268238849(%rip),%ymm14

#load
vmovdqa		(%rdi),%ymm2
vmovdqa		32(%rdi),%ymm3
vmovdqa		64(%rdi),%ymm4
vmovdqa		96(%rdi),%ymm5
vmovdqa		128(%rdi),%ymm6
vmovdqa		160(%rdi),%ymm7
vmovdqa		192(%rdi),%ymm8
vmovdqa		224(%rdi),%ymm9

fqmul_32_uniform_zeta_half 2,3
vmovdqu 32(%rsi),%ymm15
fqmul_32_uniform_zeta_half 4,5
vmovdqu 64(%rsi),%ymm15
fqmul_32_uniform_zeta_half 6,7
vmovdqu 96(%rsi),%ymm15
fqmul_32_uniform_zeta_half 8,9

#store
vmovdqa		%ymm2,(%rdi)
vmovdqa		%ymm3,32(%rdi)
vmovdqa		%ymm4,64(%rdi)
vmovdqa		%ymm5,96(%rdi)
vmovdqa		%ymm6,128(%rdi)
vmovdqa		%ymm7,160(%rdi)
vmovdqa		%ymm8,192(%rdi)
vmovdqa		%ymm9,224(%rdi)
ret

.global ntt_level7_avx_s32_268238849
ntt_level7_avx_s32_268238849:
#consts
vmovdqa     _32xq_268238849(%rip),%ymm0
vmovdqa     _32xqinv_268238849(%rip),%ymm1

level7_s32:
#zetas
vpbroadcastd (%rsi),%ymm15


#load
vmovdqa     (%rdi),%ymm2
vmovdqa     32(%rdi),%ymm3
vmovdqa     64(%rdi),%ymm4
vmovdqa     96(%rdi),%ymm5
vmovdqa     128(%rdi),%ymm6
vmovdqa     160(%rdi),%ymm7
vmovdqa     192(%rdi),%ymm8
vmovdqa     224(%rdi),%ymm9

butterfly_32_uniform_zeta_single 2,3
vpbroadcastd 4(%rsi),%ymm15
butterfly_32_uniform_zeta_single 4,5
vpbroadcastd 8(%rsi),%ymm15
butterfly_32_uniform_zeta_single 6,7
vpbroadcastd 12(%rsi),%ymm15
butterfly_32_uniform_zeta_single 8,9

#store
vmovdqa     %ymm2,(%rdi)
vmovdqa     %ymm3,32(%rdi)
vmovdqa     %ymm4,64(%rdi)
vmovdqa     %ymm5,96(%rdi)
vmovdqa     %ymm6,128(%rdi)
vmovdqa     %ymm7,160(%rdi)
vmovdqa     %ymm8,192(%rdi)
vmovdqa     %ymm9,224(%rdi)
ret

.global invntt_level2_avx_s32_268238849
invntt_level2_avx_s32_268238849:
#consts
vmovdqa		_32xq_268238849(%rip),%ymm0
vmovdqa		_32xqinv_268238849(%rip),%ymm1

ilevel2_s32:
#zetas
vpbroadcastd (%rsi),%ymm15

#barrett v
vmovdqa		_64xbarrettv_268238849(%rip),%ymm14

#load
vmovdqa		(%rdi),%ymm2
vmovdqa		32(%rdi),%ymm3
vmovdqa		64(%rdi),%ymm4
vmovdqa		96(%rdi),%ymm5
vmovdqa		128(%rdi),%ymm6
vmovdqa		160(%rdi),%ymm7
vmovdqa		192(%rdi),%ymm8
vmovdqa		224(%rdi),%ymm9

fqmul_32_uniform_zeta_single 2,3
vpbroadcastd 4(%rsi),%ymm15
fqmul_32_uniform_zeta_single 4,5
vpbroadcastd 8(%rsi),%ymm15
fqmul_32_uniform_zeta_single 6,7
vpbroadcastd 12(%rsi),%ymm15
fqmul_32_uniform_zeta_single 8,9

#store
vmovdqa		%ymm2,(%rdi)
vmovdqa		%ymm3,32(%rdi)
vmovdqa		%ymm4,64(%rdi)
vmovdqa		%ymm5,96(%rdi)
vmovdqa		%ymm6,128(%rdi)
vmovdqa		%ymm7,160(%rdi)
vmovdqa		%ymm8,192(%rdi)
vmovdqa		%ymm9,224(%rdi)
ret

.global ntt_level6_avx_s32_268238849
ntt_level6_avx_s32_268238849:
#consts
vmovdqa     _32xq_268238849(%rip),%ymm0
vmovdqa     _32xqinv_268238849(%rip),%ymm1

level6_s32:
#zetas
vpbroadcastd (%rsi),%ymm15

#load
vmovdqa     (%rdi),%ymm2
vmovdqa     32(%rdi),%ymm3
vmovdqa     64(%rdi),%ymm4
vmovdqa     96(%rdi),%ymm5
vmovdqa     128(%rdi),%ymm6
vmovdqa     160(%rdi),%ymm7
vmovdqa     192(%rdi),%ymm8
vmovdqa     224(%rdi),%ymm9

butterfly_32_uniform_zeta_double 2,3,4,5
vpbroadcastd 4(%rsi),%ymm15
butterfly_32_uniform_zeta_double 6,7,8,9
#store
vmovdqa     %ymm2,(%rdi)
vmovdqa     %ymm3,32(%rdi)
vmovdqa     %ymm4,64(%rdi)
vmovdqa     %ymm5,96(%rdi)
vmovdqa     %ymm6,128(%rdi)
vmovdqa     %ymm7,160(%rdi)
vmovdqa     %ymm8,192(%rdi)
vmovdqa     %ymm9,224(%rdi)
ret

.global invntt_level3_avx_s32_268238849
invntt_level3_avx_s32_268238849:
#consts
vmovdqa		_32xq_268238849(%rip),%ymm0
vmovdqa		_32xqinv_268238849(%rip),%ymm1

ilevel3_s32:
#zetas
vpbroadcastd (%rsi),%ymm15
#vmovdqu (%rsi),%ymm15

#barrett v
vmovdqa		_64xbarrettv_268238849(%rip),%ymm14

#load
vmovdqa		(%rdi),%ymm2
vmovdqa		32(%rdi),%ymm3
vmovdqa		64(%rdi),%ymm4
vmovdqa		96(%rdi),%ymm5
vmovdqa		128(%rdi),%ymm6
vmovdqa		160(%rdi),%ymm7
vmovdqa		192(%rdi),%ymm8
vmovdqa		224(%rdi),%ymm9

fqmul_32_uniform_zeta_single 2,4
fqmul_32_uniform_zeta_single 3,5
vpbroadcastd 4(%rsi),%ymm15
fqmul_32_uniform_zeta_single 6,8
fqmul_32_uniform_zeta_single 7,9

#store
vmovdqa		%ymm2,(%rdi)
vmovdqa		%ymm3,32(%rdi)
vmovdqa		%ymm4,64(%rdi)
vmovdqa		%ymm5,96(%rdi)
vmovdqa		%ymm6,128(%rdi)
vmovdqa		%ymm7,160(%rdi)
vmovdqa		%ymm8,192(%rdi)
vmovdqa		%ymm9,224(%rdi)
ret

.global ntt_level5_avx_s32_268238849
ntt_level5_avx_s32_268238849:
#consts
vmovdqa     _32xq_268238849(%rip),%ymm0
vmovdqa     _32xqinv_268238849(%rip),%ymm1

level5_s32:
#zetas
vpbroadcastd (%rsi),%ymm15

#load
vmovdqa     (%rdi),%ymm2
vmovdqa     32(%rdi),%ymm3
vmovdqa     64(%rdi),%ymm4
vmovdqa     96(%rdi),%ymm5
vmovdqa     128(%rdi),%ymm6
vmovdqa     160(%rdi),%ymm7
vmovdqa     192(%rdi),%ymm8
vmovdqa     224(%rdi),%ymm9

butterfly_32_uniform_zeta 2,3,4,5,6,7,8,9
#store
vmovdqa     %ymm2,(%rdi)
vmovdqa     %ymm3,32(%rdi)
vmovdqa     %ymm4,64(%rdi)
vmovdqa     %ymm5,96(%rdi)
vmovdqa     %ymm6,128(%rdi)
vmovdqa     %ymm7,160(%rdi)
vmovdqa     %ymm8,192(%rdi)
vmovdqa     %ymm9,224(%rdi)
ret

.global invntt_level4_avx_s32_268238849
invntt_level4_avx_s32_268238849:
#consts
vmovdqa		_32xq_268238849(%rip),%ymm0
vmovdqa		_32xqinv_268238849(%rip),%ymm1

ilevel4_s32:
#zetas
vpbroadcastd (%rsi),%ymm15

#barrett v
vmovdqa		_64xbarrettv_268238849(%rip),%ymm14

#load
vmovdqa		(%rdi),%ymm2
vmovdqa		32(%rdi),%ymm3
vmovdqa		64(%rdi),%ymm4
vmovdqa		96(%rdi),%ymm5
vmovdqa		128(%rdi),%ymm6
vmovdqa		160(%rdi),%ymm7
vmovdqa		192(%rdi),%ymm8
vmovdqa		224(%rdi),%ymm9

fqmul_32_uniform_zeta_single  2,6
fqmul_32_uniform_zeta_single  3,7
fqmul_32_uniform_zeta_single  4,8
fqmul_32_uniform_zeta_single  5,9

#store
vmovdqa		%ymm2,(%rdi)
vmovdqa		%ymm3,32(%rdi)
vmovdqa		%ymm4,64(%rdi)
vmovdqa		%ymm5,96(%rdi)
vmovdqa		%ymm6,128(%rdi)
vmovdqa		%ymm7,160(%rdi)
vmovdqa		%ymm8,192(%rdi)
vmovdqa		%ymm9,224(%rdi)
ret

.global ntt_level4_avx_s32_268238849
ntt_level4_avx_s32_268238849:
#consts
vmovdqa		_32xq_268238849(%rip),%ymm0
vmovdqa		_32xqinv_268238849(%rip),%ymm1

level4_s32:
#zetas
vpbroadcastd (%rsi),%ymm15

#load
vmovdqa		(%rdi),%ymm2
vmovdqa		32(%rdi),%ymm3
vmovdqa		64(%rdi),%ymm4
vmovdqa		96(%rdi),%ymm5
vmovdqa		256(%rdi),%ymm6
vmovdqa		288(%rdi),%ymm7
vmovdqa		320(%rdi),%ymm8
vmovdqa		352(%rdi),%ymm9

butterfly_32_uniform_zeta 2,3,4,5,6,7,8,9
#store
vmovdqa		%ymm2,(%rdi)
vmovdqa		%ymm3,32(%rdi)
vmovdqa		%ymm4,64(%rdi)
vmovdqa		%ymm5,96(%rdi)
vmovdqa		%ymm6,256(%rdi)
vmovdqa		%ymm7,288(%rdi)
vmovdqa		%ymm8,320(%rdi)
vmovdqa		%ymm9,352(%rdi)
ret

.global invntt_level5_avx_s32_268238849
invntt_level5_avx_s32_268238849:
#consts
vmovdqa		_32xq_268238849(%rip),%ymm0
vmovdqa		_32xqinv_268238849(%rip),%ymm1

ilevel5_s32:
#zetas
vpbroadcastd (%rsi),%ymm15

#barrett v
vmovdqa		_64xbarrettv_268238849(%rip),%ymm14

#load
vmovdqa		(%rdi),%ymm2
vmovdqa		32(%rdi),%ymm3
vmovdqa		64(%rdi),%ymm4
vmovdqa		96(%rdi),%ymm5
vmovdqa		256(%rdi),%ymm6
vmovdqa		288(%rdi),%ymm7
vmovdqa		320(%rdi),%ymm8
vmovdqa		352(%rdi),%ymm9

fqmul_32_uniform_zeta_single  2,6
fqmul_32_uniform_zeta_single  3,7
fqmul_32_uniform_zeta_single  4,8
fqmul_32_uniform_zeta_single  5,9

#store
vmovdqa		%ymm2,(%rdi)
vmovdqa		%ymm3,32(%rdi)
vmovdqa		%ymm4,64(%rdi)
vmovdqa		%ymm5,96(%rdi)
vmovdqa		%ymm6,256(%rdi)
vmovdqa		%ymm7,288(%rdi)
vmovdqa		%ymm8,320(%rdi)
vmovdqa		%ymm9,352(%rdi)
ret

.global ntt_level3_avx_s32_268238849
ntt_level3_avx_s32_268238849:
#consts
vmovdqa		_32xq_268238849(%rip),%ymm0
vmovdqa		_32xqinv_268238849(%rip),%ymm1

level3_s32:
#zetas
vpbroadcastd (%rsi),%ymm15

#load
vmovdqa		(%rdi),%ymm2
vmovdqa		32(%rdi),%ymm3
vmovdqa		64(%rdi),%ymm4
vmovdqa		96(%rdi),%ymm5
vmovdqa		512(%rdi),%ymm6
vmovdqa		544(%rdi),%ymm7
vmovdqa		576(%rdi),%ymm8
vmovdqa		608(%rdi),%ymm9

butterfly_32_uniform_zeta 2,3,4,5,6,7,8,9
#store
vmovdqa		%ymm2,(%rdi)
vmovdqa		%ymm3,32(%rdi)
vmovdqa		%ymm4,64(%rdi)
vmovdqa		%ymm5,96(%rdi)
vmovdqa		%ymm6,512(%rdi)
vmovdqa		%ymm7,544(%rdi)
vmovdqa		%ymm8,576(%rdi)
vmovdqa		%ymm9,608(%rdi)
ret

.global invntt_level6_avx_s32_268238849
invntt_level6_avx_s32_268238849:
#consts
vmovdqa		_32xq_268238849(%rip),%ymm0
vmovdqa		_32xqinv_268238849(%rip),%ymm1

ilevel6_s32:
#zetas
vpbroadcastd (%rsi),%ymm15
#vmovdqu (%rsi),%ymm15

#barrett v
vmovdqa		_64xbarrettv_268238849(%rip),%ymm14

#load
vmovdqa		(%rdi),%ymm2
vmovdqa		32(%rdi),%ymm3
vmovdqa		64(%rdi),%ymm4
vmovdqa		96(%rdi),%ymm5
vmovdqa		512(%rdi),%ymm6
vmovdqa		544(%rdi),%ymm7
vmovdqa		576(%rdi),%ymm8
vmovdqa		608(%rdi),%ymm9

fqmul_32_uniform_zeta_single  2,6
fqmul_32_uniform_zeta_single  3,7
fqmul_32_uniform_zeta_single  4,8
fqmul_32_uniform_zeta_single  5,9

#store
vmovdqa		%ymm2,(%rdi)
vmovdqa		%ymm3,32(%rdi)
vmovdqa		%ymm4,64(%rdi)
vmovdqa		%ymm5,96(%rdi)
vmovdqa		%ymm6,512(%rdi)
vmovdqa		%ymm7,544(%rdi)
vmovdqa		%ymm8,576(%rdi)
vmovdqa		%ymm9,608(%rdi)
ret

.global ntt_level2_avx_s32_268238849
ntt_level2_avx_s32_268238849:
#consts
vmovdqa     _32xq_268238849(%rip),%ymm0
vmovdqa     _32xqinv_268238849(%rip),%ymm1

level2_s32:
#zetas
vpbroadcastd (%rsi),%ymm15

#load
vmovdqa     (%rdi),%ymm2
vmovdqa     32(%rdi),%ymm3
vmovdqa     64(%rdi),%ymm4
vmovdqa     96(%rdi),%ymm5
vmovdqa     1024(%rdi),%ymm6
vmovdqa     1056(%rdi),%ymm7
vmovdqa     1088(%rdi),%ymm8
vmovdqa     1120(%rdi),%ymm9

butterfly_32_uniform_zeta 2,3,4,5,6,7,8,9
#store
vmovdqa     %ymm2,(%rdi)
vmovdqa     %ymm3,32(%rdi)
vmovdqa     %ymm4,64(%rdi)
vmovdqa     %ymm5,96(%rdi)
vmovdqa     %ymm6,1024(%rdi)
vmovdqa     %ymm7,1056(%rdi)
vmovdqa     %ymm8,1088(%rdi)
vmovdqa     %ymm9,1120(%rdi)

ret

.global invntt_level7_avx_s32_268238849
invntt_level7_avx_s32_268238849:
#consts
vmovdqa		_32xq_268238849(%rip),%ymm0
vmovdqa		_32xqinv_268238849(%rip),%ymm1

ilevel7_s32:
#zetas
vpbroadcastd (%rsi),%ymm15

#barrett v
vmovdqa		_64xbarrettv_268238849(%rip),%ymm14

#load
vmovdqa		(%rdi),%ymm2
vmovdqa		32(%rdi),%ymm3
vmovdqa		64(%rdi),%ymm4
vmovdqa		96(%rdi),%ymm5
vmovdqa		1024(%rdi),%ymm6
vmovdqa		1056(%rdi),%ymm7
vmovdqa		1088(%rdi),%ymm8
vmovdqa		1120(%rdi),%ymm9

fqmul_32_uniform_zeta_single  2,6
fqmul_32_uniform_zeta_single  3,7
fqmul_32_uniform_zeta_single  4,8
fqmul_32_uniform_zeta_single  5,9

#store
vmovdqa		%ymm2,(%rdi)
vmovdqa		%ymm3,32(%rdi)
vmovdqa		%ymm4,64(%rdi)
vmovdqa		%ymm5,96(%rdi)
vmovdqa		%ymm6,1024(%rdi)
vmovdqa		%ymm7,1056(%rdi)
vmovdqa		%ymm8,1088(%rdi)
vmovdqa		%ymm9,1120(%rdi)
ret

.global ntt_level1_avx_s32_268238849
ntt_level1_avx_s32_268238849:
#consts
vmovdqa		_32xq_268238849(%rip),%ymm0
vmovdqa		_32xqinv_268238849(%rip),%ymm1

level1_s32:
#zetas
vpbroadcastd (%rsi),%ymm15

#load
vmovdqa		(%rdi),%ymm2
vmovdqa		32(%rdi),%ymm3
vmovdqa		64(%rdi),%ymm4
vmovdqa		96(%rdi),%ymm5
vmovdqa		2048(%rdi),%ymm6
vmovdqa		2080(%rdi),%ymm7
vmovdqa		2112(%rdi),%ymm8
vmovdqa		2144(%rdi),%ymm9

butterfly_32_uniform_zeta 2,3,4,5,6,7,8,9
#store
vmovdqa		%ymm2,(%rdi)
vmovdqa		%ymm3,32(%rdi)
vmovdqa		%ymm4,64(%rdi)
vmovdqa		%ymm5,96(%rdi)
vmovdqa		%ymm6,2048(%rdi)
vmovdqa		%ymm7,2080(%rdi)
vmovdqa		%ymm8,2112(%rdi)
vmovdqa		%ymm9,2144(%rdi)

ret
