INCDIRS := -I../../openssl/include/ -I../liblicense/
LIBS := -Wl,../../openssl/libcrypto.a -Wl,../liblicense/liblicense.a

license_public : license_public.c
	gcc -o license_public -O2 $(INCDIRS) $(LIBS) license_public.c

clean :
	rm -f license_public
