INCDIRS := ../../openssl/include/
LIBDIRS := ../../openssl/
OBJS := license_sha1.o license_b64.o license_evp.o license_rsa.o
LIBS := $(LIBDIRS)libcrypto.a

liblicense.a : $(OBJS) license.h license.c
	gcc -c -O2 -I $(INCDIRS) license.c
	ar rcu liblicense.a license.o $(OBJS) $(LIBS)

license_b64.o : license_b64.c license.h
	gcc -c -O2 -I $(INCDIRS) license_b64.c

license_evp.o : license_evp.c license.h
	gcc -c -O2 -I $(INCDIRS) license_evp.c

license_rsa.o : license_rsa.c license.h
	gcc -c -O2 -I $(INCDIRS) license_rsa.c

license_sha1.o : license_sha1.c license.h
	gcc -c -O2 -I $(INCDIRS) license_sha1.c

clean :
	rm liblicense.a license.o $(OBJS)
