AUTOMAKE_OPTIONS = subdir-objects

bin_PROGRAMS = aes_enc aes_dec
aes_enc_SOURCES = src/aes/aes_enc.c \
                  src/aes/aes_common.h \
                  src/aes/ctr_common.h \
                  src/aes/file_common.h \
                  src/hash/sha2.h
aes_enc_CFLAGS = -pthread

aes_dec_SOURCES = src/aes/aes_dec.c \
                  src/aes/aes_common.h \
                  src/aes/ctr_common.h \
                  src/aes/file_common.h \
                  src/hash/sha2.h
aes_dec_CFLAGS = -pthread


# Format: tests/testABCDEF
# A: AES type (1,2,3) saved
# B: Password hash saved (0 for saved, 1 for no save)
# C: File integrity hash saved (0 for save, 1 for no save)
# D: Password hash check (0 for check, 1 for no check)
# E: File integrity hash check (0 for check, 1 for no check)

TESTS = tests/test10000.sh \
		tests/test10001.sh \
		tests/test10010.sh \
		tests/test10011.sh \
		tests/test10100.sh \
		tests/test10101.sh \
		tests/test10110.sh \
		tests/test10111.sh \
		tests/test11000.sh \
		tests/test11001.sh \
		tests/test11010.sh \
		tests/test11011.sh \
		tests/test11100.sh \
		tests/test11101.sh \
		tests/test11110.sh \
		tests/test11111.sh \
		tests/test20000.sh \
		tests/test20001.sh \
		tests/test20010.sh \
		tests/test20011.sh \
		tests/test20100.sh \
		tests/test20101.sh \
		tests/test20110.sh \
		tests/test20111.sh \
		tests/test21000.sh \
		tests/test21001.sh \
		tests/test21010.sh \
		tests/test21011.sh \
		tests/test21100.sh \
		tests/test21101.sh \
		tests/test21110.sh \
		tests/test21111.sh \
		tests/test30000.sh \
		tests/test30001.sh \
		tests/test30010.sh \
		tests/test30011.sh \
		tests/test30100.sh \
		tests/test30101.sh \
		tests/test30110.sh \
		tests/test30111.sh \
		tests/test31000.sh \
		tests/test31001.sh \
		tests/test31010.sh \
		tests/test31011.sh \
		tests/test31100.sh \
		tests/test31101.sh \
		tests/test31110.sh \
		tests/test31111.sh