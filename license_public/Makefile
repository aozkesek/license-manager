CC := clang -O2
INCDIRS := -I../../openssl/include/ -I../liblicense/
LIBDIRS := -Wl,-L../../openssl/ -Wl,-L../liblicense/
LIBS := -Wl,-llicense -Wl,-lcrypto

license_public : license_public.c
	$(CC) $(INCDIRS) $(LIBDIRS) $(LIBS) license_public.c -o license_public

clean :
	rm -f license_public
