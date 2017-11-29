
#ifndef _LICENSE_H
#define _LICENSE_H

#include "ossllib.h"

typedef struct _LICENSE_SHA_STRUCT {
	RSA *pub_provider;
	RSA *pri_client;

	unsigned char *source_sha;
	unsigned char *sha;

} LICENSE_SHA_STRUCT, *PLICENSE_SHA_STRUCT;

 
unsigned char *sha256(const unsigned char *source, const int slen, 
                        unsigned char **target);
                               
#endif //_LICENSE_H
