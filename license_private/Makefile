CC := clang -O2
INC_DIRS := -I../../openssl/include/ -I../liblicense/
LIB_DIRS := -Wl,-L../../openssl/ -Wl,-L../liblicense/
LIBS := -Wl,-llicense -Wl,-lcrypto

license_private : license_private.c
	$(CC) $(INC_DIRS) $(LIBS) $(LIB_DIRS) license_private.c -o license_private

clean :
	rm -f license_private
