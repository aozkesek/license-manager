include ../common.mk

OBJS = base64.obj crypto.obj license.obj pem.obj rsa.obj 

all : liblicense.lib

liblicense.lib : $(OBJS)
	$(AR) $(AR_OPTS) $@ $(OBJS)

.c.obj : 
	$(CC) $(DEBUG) $(CC_OPTS) -c $< $(INCDIRS)

clean :
	rm -f liblicense.lib *.o
