CC := clang -c -O2
AR := ar -ru
INC_SSL := -I ../../openssl/include/
LIB_SSL := ../../openssl/
OBJS := license_sha1.o license_b64.o license_evp.o license_rsa.o
LIBS := 

liblicense.a : $(OBJS) license.h license.c
	$(CC) $(INC_SSL) license.c
	$(AR) liblicense.a license.o $(OBJS) $(LIBS)

license_b64.o : license_b64.c license.h
	$(CC) $(INC_SSL) license_b64.c

license_evp.o : license_evp.c license.h
	$(CC) $(INC_SSL) license_evp.c

license_rsa.o : license_rsa.c license.h
	$(CC) $(INC_SSL) license_rsa.c

license_sha1.o : license_sha1.c license.h
	$(CC) $(INC_SSL) license_sha1.c

clean :
	rm -f liblicense.a license.o $(OBJS)
