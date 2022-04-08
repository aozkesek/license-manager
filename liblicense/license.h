
#ifndef _LICENSE_H
#define _LICENSE_H

#include "ossllib.h"

struct service {
	char name[118];
	char version[10];
};

struct app_license {
	char acquirer[64];
	char issuer[64];
	char version[10];

	short svcs_size;
	struct service *svcs;
}; 

char *digest(const char *src, const int srclen, char **outb);
int load_from_file(const char *fname, char **outb);

void verify_app(const char *app_version);
void verify_service(const char *app_version, const char *svc_name, const char *svc_version);
void verify_license();

void base64_selftest();
void crypto_selftest();
void rsa_selftest();
void license_selftest();

#endif //_LICENSE_H
