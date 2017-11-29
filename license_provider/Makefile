CC := clang -O2
INCDIRS := -I../../openssl/include/ -I../liblicense/
LIBDIRS := -Wl,-L../../openssl/ -Wl,-L../liblicense/
LIBS := -Wl,-llicense -Wl,-lcrypto

license_provider : license_provider.c
	$(CC) $(INCDIRS) $(LIBDIRS) $(LIBS) license_provider.c -o license_provider

clean :
	rm -f license_provider *.pem *.lic *.license
	
	
