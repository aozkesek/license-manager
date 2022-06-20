include ../common.mk

all : license_provider

license_provider : license_provider.c
	$(CC) $(DEBUG) $(CC_OPTS) $(INCDIRS) $(LIBDIRS) -o license_provider license_provider.c $(LIBS)

clean :
	rm -f license_provider *.pem *.lic *.license
	
	
