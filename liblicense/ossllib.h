
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

#define exit_on_error(e) \
        exit_on_error_m(__FILE__, __FUNCTION__, __LINE__, e)

#define RSA_CRYPT(p, e, fl, f, t, r) \
        RSA_ ## p ## _ ## e (fl, f, t, r, RSA_PKCS1_PADDING)
        
extern void program_exit(int exit_code);

void crypto_init();
void crypto_final();
void print_last_error();
void reallocate(unsigned char **p, int s);
void exit_on_error_m(const char *filename, const char *function_name, 
                        int line_number, int error_code);
void cleanup_on_error(EVP_CIPHER_CTX *ctx, int error_code);

int crypto_check(EVP_CIPHER_CTX *ctx, const unsigned char *source, int slen, 
                unsigned char **target, const unsigned char *session_key);
int encrypt(const unsigned char *source, int slen, unsigned char **target, 
                const unsigned char *session_key);
int decrypt(const unsigned char *source, int slen, unsigned char **target, 
                const unsigned char *session_key);

int public_encrypt_base64_buffer(int slen, unsigned char *source, 
                                unsigned char **target, RSA *rsa);
int private_encrypt_base64_buffer(int slen, unsigned char *source, 
                                unsigned char **target, RSA *rsa);
int public_decrypt_base64_buffer(unsigned char *source, 
                                unsigned char **target, RSA *rsa);
int private_decrypt_base64_buffer(unsigned char *source, 
                                unsigned char **target, RSA *rsa);
                                
void publickey_write_to_file(const char *fileName, RSA *rsa);
void privatekey_write_to_file(const char *fileName, RSA* rsa);
RSA *rsa_reset_key_files(const char *pri_pem, const char *pub_pem);
RSA *publickey_read_from_file(const char *fileName);
RSA *privatekey_read_from_file(const char *fileName);
RSA *rsa_publickey_read_from_file(const char *fname);
RSA *rsa_publickey_load_from_file(const char *fname);
RSA *rsa_privatekey_read_from_file(const char *fname);
RSA *rsa_privatekey_load_from_file(const char *fname);

int base64_decode(const unsigned char *source, unsigned char **target);
unsigned char *base64_encode(const unsigned char *source, const int slen, 
                                unsigned char **target);
unsigned char *hex_encode(const unsigned char *source, const int slen, 
                        unsigned char **target);
                                
void base64_write_to_file(const unsigned char *b64, FILE *fd);
                               
#endif //_OSSLLIB_H