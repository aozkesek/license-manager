DEBUG = -g
INCDIRS = -I"..\liblicense" -I"..\..\openssl\include"
LIBDIRS = -L"..\liblicense"
LIBS = -llicense -lcrypto

CC = clang
CC_OPTS = -Werror --std=c11
AR = llvm-ar
AR_OPTS = rcus

