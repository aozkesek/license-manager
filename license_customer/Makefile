CC := gcc -O2
INCDIRS := -I../../openssl/dist/include/ -I../liblicense/
LIBDIRS := -L../../openssl/dist/lib/ -L../liblicense/
LIBS := -llicense -lcrypto

license_customer : license_customer.c
	$(CC) -o license_customer $(INCDIRS) license_customer.c $(LIBDIRS) $(LIBS)  

clean :
	rm -f license_customer *.pem *.lic
