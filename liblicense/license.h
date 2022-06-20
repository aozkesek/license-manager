
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

/**
 * extracts the sub-value between begin-tag and end-tag and trim new line(s) in it;
 *
 * @src source text buffer
 * @tbegin begin tag/keyword
 * @tend end tag/keyword
 */
char *ext_subval_ex(const char *src, const char *tbegin, const char *tend);
/**
 * extracts the sub-value between begin-tag and end-tag;
 *
 * @src source text buffer
 * @tbegin begin tag/keyword
 * @tend end tag/keyword
 */
char *ext_subval(const char *src, const char *tbegin, const char *tend);

char *digest(const char *src, const int srclen, char **outb);
int load_from_file(const char *fname, char **outb);

void verify_app(const char *app_version);
void verify_service(const char *app_version, const char *svc_name, const char *svc_version);
char *verify_license();

#endif //_LICENSE_H
