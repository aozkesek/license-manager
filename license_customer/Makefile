CC := clang -O2
INCDIRS := -I../../openssl/include/ -I../liblicense/
LIBDIRS := -Wl,-L../../openssl/ -Wl,-L../liblicense/
LIBS := -Wl,-llicense -Wl,-lcrypto

license_customer : license_customer.c
	$(CC) $(INCDIRS) $(LIBDIRS) $(LIBS) license_customer.c -o license_customer

clean :
	rm -f license_customer *.pem *.lic
