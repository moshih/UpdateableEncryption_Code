CC = /usr/bin/gcc
NISTFLAGS = -O3 -fomit-frame-pointer -march=native -fPIC -no-pie
UTILS_DIR = ../utils

DEPS = $(UTILS_DIR)/aes_ctr.c $(UTILS_DIR)/aes_ctr.h $(UTILS_DIR)/aes_gcm.c $(UTILS_DIR)/aes_gcm.h AE_Nested_AES.c AE_Nested_AES.h

all:	AES_NESTED

AES_NESTED: $(DEPS)
	$(CC) $(NISTFLAGS) -I$(UTILS_DIR) $(DEPS) -msse2avx -mavx2 test_aes_nested.c -o aes_nested -lcrypto

.PHONY: clean

clean:
	-rm aes_nested


