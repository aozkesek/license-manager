include ../make.inc

OBJS := base64.o crypto.o license.o pem.o rsa.o 

liblicense.a : $(OBJS)
	$(AR) $@ $(OBJS)

%.o : %.c license.h ossllib.h
	$(CC) -c $< $(INCDIRS)

clean :
	rm -f liblicense.a *.o
