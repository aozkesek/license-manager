include ../common.mk

all : license_customer

license_customer : license_customer.c
	$(CC) $(DEBUG) $(CC_OPTS) $(INCDIRS) $(LIBDIRS) -o license_customer license_customer.c $(LIBS)  

clean :
	rm -f license_customer *.pem *.lic
