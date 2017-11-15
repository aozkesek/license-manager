#ifndef _LICENSE_H
#define _LICENSE_H

#ifndef _WIN32
	#define __stdcall
	#define __declspec(dllexport)
	#define _MAX_PATH PATH_MAX

	#include <limits.h>
#endif

#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>

typedef enum { false, true } bool;
typedef unsigned char byte;

typedef struct _SERVICE_STRUCT
{
	char *service_name;
	char *service_version;

} SERVICE_STRUCT, *PSERVICE_STRUCT;

typedef struct _LICENSE_STRUCT
{

	char *license_version;
	char *license_acquirer;
	char *license_issuer;
	int license_service_size;
	PSERVICE_STRUCT license_services;

} LICENSE_STRUCT, *PLICENSE_STRUCT;

#define print_last_error() print_last_error_m(__FILE__, __FUNCTION__, __LINE__)
#define exit_on_error() exit_on_error_m(__FILE__, __FUNCTION__, __LINE__)

extern void program_exit(int error_code);

// WARNING: you can only call this vvv from the managed code.
__declspec(dllexport) int __stdcall LicenseSha1(const char *pem_path, byte *source, byte *sha1a, byte *sha1b);
// WARNING: you can only call this ^^^ in managed code.

// do not call any of these from the managed code,
// it is not guaranteed not to get an access violation error.
__declspec(dllexport) void __stdcall lib_initialize();
__declspec(dllexport) void __stdcall lib_finalize();

__declspec(dllexport) byte * __stdcall reallocate(byte **b, int blen);
__declspec(dllexport) byte * __stdcall sha1(const byte *source, const int slen, byte **target);

__declspec(dllexport) int __stdcall base64_decode(const byte *source, byte **target);
__declspec(dllexport) byte * __stdcall base64_encode(const byte *source, const int slen, byte **target);
__declspec(dllexport) void __stdcall base64_write_to_file(const byte *b64, FILE *fd);
__declspec(dllexport) byte * __stdcall hex_encode(const byte *source, const int slen, byte **target);

__declspec(dllexport) PLICENSE_STRUCT __stdcall license_init(int argc, const char **argv);
__declspec(dllexport) void __stdcall license_free(PLICENSE_STRUCT plicense);
__declspec(dllexport) int __stdcall license_size(PLICENSE_STRUCT license);
__declspec(dllexport) char * __stdcall license_to_json_string(PLICENSE_STRUCT plicense, char **slicense);
__declspec(dllexport) void __stdcall license_print(PLICENSE_STRUCT pLicense);
__declspec(dllexport) byte * __stdcall load_from_file(const char *fname);
__declspec(dllexport) char * __stdcall sub_value_extract(const char *lic_client, const char *begin_title, const char *end_title);
__declspec(dllexport) char * __stdcall sub_value_extract_trim(const char *lic_client, const char *begin_title, const char *end_title);

//read/write key functions
__declspec(dllexport) void __stdcall publickey_write_to_file(const char *fileName, RSA* rsa);
__declspec(dllexport) void __stdcall privatekey_write_to_file(const char *fileName, RSA* rsa, const byte *u);
__declspec(dllexport) RSA * __stdcall rsa_publickey_load_from_file(const char *fname);
__declspec(dllexport) RSA * __stdcall rsa_privatekey_load_from_file(const char *fname);
__declspec(dllexport) RSA * __stdcall rsa_publickey_read_from_file(const char *fname);
__declspec(dllexport) RSA * __stdcall rsa_privatekey_read_from_file(const char *fname);

__declspec(dllexport) byte * __stdcall generate_random_key(byte **random_key, int klen);

//session key encrypt/decrypt functions
__declspec(dllexport) int __stdcall public_encrypt_buffer(int slen, byte *source, byte *target, RSA *rsa);
__declspec(dllexport) int __stdcall public_decrypt_buffer(int slen, byte *source, byte *target, RSA *rsa);
__declspec(dllexport) int __stdcall private_encrypt_buffer(int slen, byte *source, byte *target, RSA *rsa);
__declspec(dllexport) int __stdcall private_decrypt_buffer(int slen, byte *source, byte *target, RSA *rsa);

__declspec(dllexport) int __stdcall public_encrypt_b64(int slen, byte *source, byte **target, RSA *rsa);
__declspec(dllexport) int __stdcall public_decrypt_b64(byte *source, byte **target, RSA *rsa);
__declspec(dllexport) int __stdcall private_encrypt_b64(int slen, byte *source, byte **target, RSA *rsa);
__declspec(dllexport) int __stdcall private_decrypt_b64(byte *source, byte **target, RSA *rsa);

//message encrypt/decrpyt functions
__declspec(dllexport) int __stdcall encrypt(const byte *source, const int slen, byte **target, const byte *session_key);
__declspec(dllexport) int __stdcall decrypt(const byte *source, const int slen, byte **target, const byte *session_key);

//do not call in non-console application.  the output goes to console's stdout.
__declspec(dllexport) void __stdcall print_last_error_m(const char *file_name, const char *function_name, const int line_number);
__declspec(dllexport) void __stdcall exit_on_error_m(const char *file_name, const char *function_name, const int line_number);


#endif //_LICENSE_H
