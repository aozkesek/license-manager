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
typedef enum { decrypt, encrypt } crypto;
typedef unsigned char byte;

typedef struct _NIPPS_STRUCT
{
	byte *Name;
	byte *Version;

} NIPPS_STRUCT, *PNIPPS_STRUCT;

typedef struct _LICENSE_STRUCT
{

	byte *Version;
	byte *Licensed_To;
	byte *Issued_By;
	int Service_Count;
	PNIPPS_STRUCT Services;

} LICENSE_STRUCT, *PLICENSE_STRUCT;

// WARNING: you can only call this vvv from the managed code.  
__declspec(dllexport) int __stdcall LicenseSha1(byte *pem_path, byte *source, byte *sha1a, byte *sha1b);
// WARNING: you can only call this ^^^ in managed code.  


// do not call any of these from the managed code,
// it is not guaranteed not to get an access violation error.

__declspec(dllexport) byte * __stdcall reallocate(byte **b, int blen);
__declspec(dllexport) byte * __stdcall sha1(byte *source, int slen, byte **target);

__declspec(dllexport) int __stdcall decode_b64(byte *source, byte **target);
__declspec(dllexport) byte * __stdcall encode_b64(byte *source, int slen, byte **target);
__declspec(dllexport) void __stdcall b64_write_to_file(byte *b64, FILE *fd);
__declspec(dllexport) byte * __stdcall encode_hex(byte *source, int slen, byte **target);

__declspec(dllexport) PLICENSE_STRUCT __stdcall init_license(int argc, byte **argv);
__declspec(dllexport) void __stdcall free_license(PLICENSE_STRUCT plicense);
__declspec(dllexport) int __stdcall license_size(PLICENSE_STRUCT license);
__declspec(dllexport) byte * __stdcall license_to_string(PLICENSE_STRUCT plicense, byte **slicense);
__declspec(dllexport) void __stdcall print_license(PLICENSE_STRUCT pLicense);
__declspec(dllexport) byte * __stdcall load_from_file(byte *fname);
__declspec(dllexport) byte * __stdcall extract_subs(byte *lic_client, byte *begin_title, byte *end_title, bool trim);

//read/write key functions
__declspec(dllexport) void __stdcall write_publickey(byte *fileName, RSA* rsa);
__declspec(dllexport) void __stdcall write_privatekey(byte *fileName, RSA* rsa, byte *u);
__declspec(dllexport) RSA * __stdcall load_key(byte *fname, bool fcreate, bool public);

__declspec(dllexport) byte * __stdcall generate_random_key(byte **random_key, int klen);

//session key encrypt/decrypt functions
__declspec(dllexport) int __stdcall public_encrypt(int slen, byte *source, byte *target, RSA *rsa);
__declspec(dllexport) int __stdcall public_decrypt(int slen, byte *source, byte *target, RSA *rsa);
__declspec(dllexport) int __stdcall private_encrypt(int slen, byte *source, byte *target, RSA *rsa);
__declspec(dllexport) int __stdcall private_decrypt(int slen, byte *source, byte *target, RSA *rsa);

__declspec(dllexport) int __stdcall public_encrypt_b64(int slen, byte *source, byte **target, RSA *rsa);
__declspec(dllexport) int __stdcall public_decrypt_b64(byte *source, byte **target, RSA *rsa);
__declspec(dllexport) int __stdcall private_encrypt_b64(int slen, byte *source, byte **target, RSA *rsa);
__declspec(dllexport) int __stdcall private_decrypt_b64(byte *source, byte **target, RSA *rsa);

//message encrypt/decrpyt functions
__declspec(dllexport) int __stdcall crypt(byte *source, int slen, byte **target, byte *session_key, crypto c);

//do not call in non-console application.  the output goes to console's stdout.
__declspec(dllexport) void __stdcall print_last_error();


#endif //_LICENSE_H

