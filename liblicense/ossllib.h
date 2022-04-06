
#ifndef _OSSLLIB_H
#define _OSSLLIB_H

#include <stdlib.h>
#include <string.h>
#include <memory.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#define EENCFAIL -0x0101
#define EENCINIT -0x0102
#define EENCUPDT -0x0103
#define EENCFINL -0x0104

#define EDECFAIL -0x0201
#define EDECINIT -0x0202
#define EDECUPDT -0x0203
#define EDECFINL -0x0204

#define EB64FAIL -0x0301
#define EB64WRFL -0x0302
#define EB64RDFL -0x0303

#define ESHAFAIL -0x0401

#define ERSAFAIL -0x0501
#define ERSAWRFL -0x0502
#define ERSARDFL -0x0503

#define EPEMFAIL -0x0601
#define EPEMWRFL -0x0602
#define EPEMRDFL -0x0603

#define ELICFAIL -0x1101
#define ELICINIT -0x1102
#define ELICUPDT -0x1103
#define ELICFINL -0x1104

#define ERDFILE -0x2001
#define EWRFILE -0x2002

#define RSA_KSIZE 2048
/*
 * we do use rsa pri/pub encrypt/decrypt for session key, and
 * we do want to do only one time/call, so better keep session key length is less
 *
 * max session key size is equal (rsa key size (2048) / 8) - 17
 *
 * */
#define MAX_SESSION_KSIZE 256 - 17

#define on_error(e) \
	exit_on_error(__FILE__, __FUNCTION__, __LINE__, e)

#define reallocate(pp, i) { \
	if (pp) { \
		if (*pp) free(*pp); \
		*pp = malloc(i); \
		memset(*pp, 0, i); \
	} }

extern const char *prov_pri_pem;
extern const char *prov_pub_pem;
extern const char *cli_pri_pem;
extern const char *cli_pub_pem;
extern const char *client_lic;
extern const char *client_license;

extern const char *begin_session;
extern const char *end_session;
extern const char *begin_key;
extern const char *end_key;
extern const char *begin_license;
extern const char *end_license;
extern const char *begin_license_sha_a;
extern const char *end_license_sha_a;
extern const char *begin_license_sha_b;
extern const char *end_license_sha_b;
extern void (*onerror)(int);

void crypto_init(void (*on_err)(int));
void crypto_final();

void exit_on_error(const char *fname, const char *fnname, int line, int error);
void cleanup_on_error(EVP_CIPHER_CTX *ctx, int error);

int encrypt(const char *src, int srclen, char **target, const char *session_key);
int decrypt(const char *src, int srclen, char **target, const char *session_key);

int pub_encrypt(int srclen, char *src, char **target, RSA *rsa);
int pri_encrypt(int srclen, char *src, char **target, RSA *rsa);
int pub_decrypt(char *src, char **target, RSA *rsa);
int pri_decrypt(char *src, char **target, RSA *rsa);

void save_pubkey(const char *fname, RSA* rsa);
void save_prikey(const char *fname, RSA* rsa);
RSA *reset_key(const char *pri_pem, const char *pub_pem);
RSA *load_pubkey(const char *fname);
RSA *load_prikey(const char *fname);
RSA *get_pubkey(const char *fname);
RSA *get_pubkey_ex(const char *fname);
RSA *get_prikey(const char *fname);
RSA *get_prikey_ex(const char *fname);

void base64_write_to_file(const char *b64, FILE *fd);

void program_exit(int exit_code);
int gen_session_key(int klen, char **random_key);
int base64_decode(const char *src, const int srclen, char **target);
char *base64_encode(const char *src, const int srclen, char **target);
char *hex_encode(const char *src, const int srclen, char **target);

int crypto_check(EVP_CIPHER_CTX *ctx, const char *src, int srclen,
		 char **target, const char *session_key);


#endif //_OSSLLIB_H
