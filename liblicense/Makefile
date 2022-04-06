include ../common.mk

OBJS := base64.o crypto.o license.o pem.o rsa.o 

all : liblicense.a

liblicense.a : $(OBJS)
	$(AR) $(AR_OPTS) $@ $(OBJS)

%.o : %.c license.h ossllib.h
	$(CC) $(DEBUG) $(CC_OPTS) -c $< $(INCDIRS)

clean :
	rm -f liblicense.a *.o
