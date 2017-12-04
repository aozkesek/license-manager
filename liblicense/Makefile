CC := gcc -c -O2
AR := ar rcus
CCINCDIRS := -I ../../openssl/dist/include/
OBJS := base64.o crypto.o license.o pem.o rsa.o 

liblicense.a : $(OBJS)
	$(AR) $@ $(OBJS)

%.o : %.c license.h ossllib.h
	$(CC) $(CCINCDIRS) $<

clean :
	rm -f liblicense.a *.o
