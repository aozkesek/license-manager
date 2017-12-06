
INCDIRS := -I../../openssl/dist/include/ -I../liblicense/
LIBDIRS := -L../../openssl/dist/lib/ -L../liblicense/
LIBS := -llicense -lcrypto

CC := gcc -O2 
AR := ar rcus 


