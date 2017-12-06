include ../make.inc

all: license_provider

license_provider : license_provider.c
	$(CC) -o license_provider license_provider.c $(INCDIRS) $(LIBDIRS) $(LIBS)

clean :
	rm -f license_provider *.pem *.lic *.license
	
	
