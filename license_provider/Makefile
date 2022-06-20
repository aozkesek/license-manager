include ../common.mk

all: license_provider.lib

license_provider.lib : license_provider.c
	$(CC) $(DEBUG) $(CC_OPTS) $(INCDIRS) $(LIBDIRS) -o license_provider.lib license_provider.c $(LIBS)

clean:
	del /Q license_provider.lib *.pem *.lic *.license
		
