INCDIRS := -I../../openssl/include/ -I../liblicense/
LIBS := ../../openssl/libcrypto.a ../liblicense/liblicense.a

license_private : license_private.c
	gcc -o license_private -O2 $(INCDIRS) -Wl,$(LIBS) license_private.c

clean :
	rm license_private
