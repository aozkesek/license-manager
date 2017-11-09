INCDIRS := -I../../openssl/include/ -I../liblicense/
LIBS := ../../openssl/libcrypto.a ../liblicense/liblicense.a

license_public : license_public.c
	gcc -o license_public -O2 $(INCDIRS) -Wl,$(LIBS) license_public.c

clean :
	rm license_public
