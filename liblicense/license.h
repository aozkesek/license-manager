
#ifndef _LICENSE_H
#define _LICENSE_H

#include "ossllib.h"

typedef struct _LICENSE_SHA_STRUCT {
	RSA *pub_provider;
	RSA *pri_client;

	unsigned char *source_sha;
	unsigned char *sha;

} LICENSE_SHA_STRUCT, *PLICENSE_SHA_STRUCT;

typedef struct _SERVICE_STRUCT {
        char name[118];
        char version[10];        
} SERVICE_STRUCT, *PSERVICE_STRUCT;

typedef struct _LICENSE_STRUCT {
        char acquirer[64];
        char issuer[64];
        char version[10];
        
        short service_size;
        PSERVICE_STRUCT services;
        
} LICENSE_STRUCT, *PLICENSE_STRUCT; 
 
unsigned char *sha256(const unsigned char *source, const int slen, 
                        unsigned char **target);
int load_from_file(const char *fname, unsigned char **buffer);
void license_sha(unsigned char *source, unsigned char *sha_a, 
                unsigned char *sha_b);
void license_for_app(const char *app_version);                         
void license_for_service(const char *app_version, const char *svc_name, 
                const char *svc_version);                         
#endif //_LICENSE_H
