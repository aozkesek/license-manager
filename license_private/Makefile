CC := clang -O2
INCDIRS := -I../../openssl/include/ -I../liblicense/
LIBDIRS := -Wl,-L../../openssl/ -Wl,-L../liblicense/
LIBS := -Wl,-llicense -Wl,-lcrypto

license_private : license_private.c
	$(CC) $(INCDIRS) $(LIBDIRS) $(LIBS) license_private.c -o license_private

clean :
	rm -f license_private
