CC := clang -c -O2
LD := ld -S -x 
INC_DIRS := -I../../openssl/include/ -I../liblicense/
LIB_DIRS := -L../../openssl/ -L../liblicense/
LIBS := -llicense -lcrypto

license_private : license_private.c
	$(CC) $(INC_DIRS) license_private.c
	$(LD) license_private.o $(LIBS) $(LIB_DIRS) -lc -o license_private

clean :
	rm -f license_private
