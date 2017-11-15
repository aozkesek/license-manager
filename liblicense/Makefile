CC := clang -c -O2
AR := ar -ru
CCINCDIRS := -I ../../openssl/include/
OBJS := license.o license_b64.o license_evp.o license_rsa.o license_sha1.o

liblicense.a : $(OBJS)
	$(AR) $@ $(OBJS)

%.o : %.c license.h
	$(CC) $(CCINCDIRS) $<

clean :
	rm -f liblicense.a *.o
