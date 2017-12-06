include ../make.inc

all: license_customer

license_customer : license_customer.c
	$(CC) -o license_customer license_customer.c $(INCDIRS) $(LIBDIRS) $(LIBS)  

clean :
	rm -f license_customer *.pem *.lic
