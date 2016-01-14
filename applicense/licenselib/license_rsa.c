#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <memory.h>
#include <string.h>

#include "license.h"

extern const byte b64[];

const byte u[] = 
	{ 1, 2, 3, 5, 8, 13, 21, 34, 0 };
	
void __stdcall write_publickey(byte *fileName, RSA* rsa) {

    BIO* bp = BIO_new_file(fileName, "w+");
    if (bp) {
		int rc = PEM_write_bio_RSAPublicKey(bp, rsa);
		if (rc != 1)
			print_last_error();
		BIO_free(bp);
    } 
	else
		print_last_error();
}

RSA *__stdcall read_publickey(byte *fileName) {

    BIO* bp = BIO_new_file(fileName, "r");
    if (bp) {
		RSA* rc = PEM_read_bio_RSAPublicKey(bp, NULL, NULL, NULL);
		if (!rc)
			print_last_error();

		BIO_free(bp);
		return rc;
    } 
	else
		print_last_error();
		
    return NULL;
}

void __stdcall write_privatekey(byte *fileName, RSA* rsa, byte *u) {

    BIO* bp = BIO_new_file(fileName, "w+");
    if (bp) {
		int rc = PEM_write_bio_RSAPrivateKey(bp, rsa, NULL, NULL, 0, NULL, u);
		if (rc != 1)
			print_last_error();
		BIO_free(bp);
    } 
	else
		print_last_error();
}

RSA *__stdcall read_privatekey(byte *fileName, byte *u) {

    BIO* bp = BIO_new_file(fileName, "r");
    if (bp) {
		RSA* rc = PEM_read_bio_RSAPrivateKey(bp, NULL, NULL, u);
		if (!rc)
			print_last_error();

		BIO_free(bp);
		return rc;
    } 
	else
		print_last_error();

    return NULL;
}

int __stdcall public_encrypt(int slen, byte *source, byte *target, RSA *rsa)  {
	return RSA_public_encrypt(slen, source, target, rsa, RSA_PKCS1_PADDING);
}

int __stdcall public_decrypt(int slen, byte *source, byte *target, RSA *rsa)  {
	return RSA_public_decrypt(slen, source, target, rsa, RSA_PKCS1_PADDING);
}

int __stdcall private_encrypt(int slen, byte *source, byte *target, RSA *rsa)  {
	return RSA_private_encrypt(slen, source, target, rsa, RSA_PKCS1_PADDING);
}

int __stdcall private_decrypt(int slen, byte *source, byte *target, RSA *rsa)  {
	return RSA_private_decrypt(slen, source, target, rsa, RSA_PKCS1_PADDING);
}

int encrypt_b64(int slen, byte *source, byte **target, RSA *rsa, bool private) {

	if (!rsa)
		return -1;

	int enc_size = RSA_size(rsa);

	if (!source || !target || slen >= enc_size - 11)
		return -2;

	byte *enc_buffer = malloc(enc_size);
	memset(enc_buffer, 0, enc_size);

	int elen;
	if (private == true)
		elen = RSA_private_encrypt(slen, source, enc_buffer, rsa, RSA_PKCS1_PADDING);
	else
		elen = RSA_public_encrypt(slen, source, enc_buffer, rsa, RSA_PKCS1_PADDING);
	
	if (elen < enc_size) {
		free(enc_buffer);
		return -3;
	}

	byte *b64 = encode_b64(enc_buffer, elen, target);

	free(enc_buffer);

	if (!b64)
		return -4;

	return strlen(b64);

}

int decrypt_b64(byte *source, byte **target, RSA *rsa, bool private)  {

	if (!rsa)
		return -1;

	int enc_size = RSA_size(rsa);

	if (!source || enc_size >= strlen(source))
		return -2;

	if (!target)
		return -3;

	byte *enc_buffer = NULL;
	int elen = decode_b64(source, &enc_buffer);
	if (elen != enc_size) {
		if (elen > 0)
			free(enc_buffer);
		return -4;
	}

	reallocate(target, elen - 11);

	if (private == true)
		elen = RSA_private_decrypt(elen, enc_buffer, *target, rsa, RSA_PKCS1_PADDING);
	else
		elen = RSA_public_decrypt(elen, enc_buffer, *target, rsa, RSA_PKCS1_PADDING);

	free(enc_buffer);

	return elen > 0 ? elen : -5;

}

int __stdcall public_encrypt_b64(int slen, byte *source, byte **target, RSA *rsa)  {
	return encrypt_b64(slen, source, target, rsa, false);
}

int __stdcall public_decrypt_b64(byte *source, byte **target, RSA *rsa)  {
	return decrypt_b64(source, target, rsa, false);
}

int __stdcall private_encrypt_b64(int slen, byte *source, byte **target, RSA *rsa)  {
	return encrypt_b64(slen, source, target, rsa, true);
}

int __stdcall private_decrypt_b64(byte *source, byte **target, RSA *rsa)  {
	return decrypt_b64(source, target, rsa, true);
}

byte *__stdcall generate_random_key(byte **random_key, int klen) {
	
	if (!random_key)
		return NULL;
		
	if (klen < 16)
		klen = 16;

	if (!*random_key)
		free(*random_key);

	*random_key = malloc(klen + 1);
	memset(*random_key, 0, klen + 1);
	
	int i;
	for (i = 0; i < klen; i++)
		(*random_key)[i] = b64[rand() % 64];
	
	return *random_key; 
}

void initialize() {
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);
	srand(time(0));
}

void finalize() {
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
}

void __stdcall print_last_error() {
	char last_error[4000];
	ERR_error_string(ERR_get_error(), last_error);
	printf("vvv crypto last error vvv\n\t%s\n", last_error);	
}

RSA *__stdcall load_key(byte *fname, bool fcreate, bool public) {
    struct stat filestat;
    RSA* rsa;
    int rc;

    rc = stat(fname, &filestat);
    if (rc) {
		
		if (!fcreate)
			return NULL;
			
		BIGNUM* e = BN_new();
		BN_set_word(e, RSA_F4);

		rsa = RSA_new();
		if (!rsa) {
			print_last_error();
			return NULL;
		}
		
		rc = RSA_generate_key_ex(rsa, 2048, e, NULL);
		if (rc) 
			write_privatekey(fname, rsa, u);
		else
			print_last_error();

		BN_free(e);
    } 
	else {
		if (public)
			rsa = read_publickey(fname);
		else
			rsa = read_privatekey(fname, u);
    }

    return rsa;
}
