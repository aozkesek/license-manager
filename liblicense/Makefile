CC := clang -c -O2
AR := ar -ru
CCINCDIRS := -I ../../openssl/include/
OBJS := license.o base64.o crypto.o rsa.o pem.o

liblicense.a : $(OBJS)
	$(AR) $@ $(OBJS)

%.o : %.c license.h ossllib.h
	$(CC) $(CCINCDIRS) $<

clean :
	rm -f liblicense.a *.o
