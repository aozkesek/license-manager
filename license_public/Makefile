CC := clang -O2
INC_DIRS := -I../../openssl/include/ -I../liblicense/
LIB_DIRS := -Wl,-L../../openssl/ -Wl,-L../liblicense/
LIBS := -Wl,-llicense -Wl,-lcrypto

license_public : license_public.c
	$(CC) $(INC_DIRS) $(LIBS) $(LIB_DIRS) license_public.c -o license_public

clean :
	rm -f license_public
