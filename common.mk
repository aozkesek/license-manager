DEBUG := -g
INCDIRS := -I../liblicense/
LIBDIRS := -L../liblicense/
LIBS := -llicense -lcrypto

CC := gcc
CC_OPTS := -Werror --std=c11
AR := ar
AR_OPTS := rcus

