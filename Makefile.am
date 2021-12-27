AUTOMAKE_OPTIONS = subdir-objects

bin_PROGRAMS = aes_enc
aes_enc_SOURCES = src/aes/aes_enc.c \
                  src/aes/aes_common.h \
                  src/aes/ctr_common.h \
                  src/aes/file_common.h \
                  src/hash/sha2.h
aes_enc_CFLAGS = -pthread

