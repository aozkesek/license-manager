
#ifndef _LICENSE_H
#define _LICENSE_H

#include "ossllib.h"

struct sha {
	RSA *pub_provider;
	RSA *pri_client;

	char *src_sha;
	char *sha;
};

struct service {
	char name[118];
	char version[10];
};

struct application {
	char acquirer[64];
	char issuer[64];
	char version[10];

	short svcs_size;
	struct service *svcs;
}; 

char *sha256(const char *src, const int srclen, char **target);
int load_from_file(const char *fname, char **buffer);
void build_sha(char *source, char *sha_a, char *sha_b);
void license_app(const char *app_version);
void license_service(const char *app_version, const char *svc_name, const char *svc_version);

void base64_selftest();
void crypto_selftest();
void rsa_selftest();

#endif //_LICENSE_H
