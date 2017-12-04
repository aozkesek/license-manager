CC := gcc -O2
INCDIRS := -I../../openssl/dist/include/ -I../liblicense/
LIBDIRS := -L../../openssl/dist/lib/ -L../liblicense/
LIBS := -llicense -lcrypto

license_provider : license_provider.c
	$(CC) -o license_provider $(INCDIRS) license_provider.c $(LIBDIRS) $(LIBS)

clean :
	rm -f license_provider *.pem *.lic *.license
	
	
