#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <memory.h>
#include <string.h>

#include "license.h"

extern const byte b64[];

const byte u[] =
	{ 1, 2, 3, 5, 8, 13, 21, 34, 0 };

void __stdcall publickey_write_to_file(byte *fileName, RSA* rsa) {

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

RSA *__stdcall publickey_read_from_file(byte *fileName) {

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

void __stdcall privatekey_write_to_file(byte *fileName, RSA* rsa, byte *u) {

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

RSA *__stdcall privatekey_read_from_file(byte *fileName, byte *u) {

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

int __stdcall public_encrypt_buffer(int slen, byte *source, byte *target, RSA *rsa)  {
	return RSA_public_encrypt(slen, source, target, rsa, RSA_PKCS1_PADDING);
}

int __stdcall public_decrypt_buffer(int slen, byte *source, byte *target, RSA *rsa)  {
	return RSA_public_decrypt(slen, source, target, rsa, RSA_PKCS1_PADDING);
}

int __stdcall private_encrypt_buffer(int slen, byte *source, byte *target, RSA *rsa)  {
	return RSA_private_encrypt(slen, source, target, rsa, RSA_PKCS1_PADDING);
}

int __stdcall private_decrypt_buffer(int slen, byte *source, byte *target, RSA *rsa)  {
	return RSA_private_decrypt(slen, source, target, rsa, RSA_PKCS1_PADDING);
}

int public_encrypt_base64_buffer(int slen, byte *source, byte **target, RSA *rsa) {

	if (!rsa)
		return -1;

	int enc_size = RSA_size(rsa);

	if (!source || !target || slen >= enc_size - 11)
		return -2;

	byte *enc_buffer = malloc(enc_size);
	memset(enc_buffer, 0, enc_size);

	int elen;
	elen = RSA_public_encrypt(slen, source, enc_buffer, rsa, RSA_PKCS1_PADDING);

	if (elen < enc_size) {
		free(enc_buffer);
		return -3;
	}

	byte *b64 = base64_encode(enc_buffer, elen, target);

	free(enc_buffer);

	if (!b64)
		return -4;

	return strlen(b64);

}

int private_encrypt_base64_buffer(int slen, byte *source, byte **target, RSA *rsa) {

	if (!rsa)
		return -1;

	int enc_size = RSA_size(rsa);

	if (!source || !target || slen >= enc_size - 11)
		return -2;

	byte *enc_buffer = malloc(enc_size);
	memset(enc_buffer, 0, enc_size);

	int elen;
	elen = RSA_private_encrypt(slen, source, enc_buffer, rsa, RSA_PKCS1_PADDING);

	if (elen < enc_size) {
		free(enc_buffer);
		return -3;
	}

	byte *b64 = base64_encode(enc_buffer, elen, target);

	free(enc_buffer);

	if (!b64)
		return -4;

	return strlen(b64);

}

int public_decrypt_base64_buffer(byte *source, byte **target, RSA *rsa)  {

	if (!rsa)
		return -1;

	int enc_size = RSA_size(rsa);

	if (!source || enc_size >= strlen(source))
		return -2;

	if (!target)
		return -3;

	byte *enc_buffer = NULL;
	int elen = base64_decode(source, &enc_buffer);
	if (elen != enc_size) {
		if (elen > 0)
			free(enc_buffer);
		return -4;
	}

	reallocate(target, elen - 11);

	elen = RSA_public_decrypt(elen, enc_buffer, *target, rsa, RSA_PKCS1_PADDING);

	free(enc_buffer);

	return elen > 0 ? elen : -5;

}

int private_decrypt_base64_buffer(byte *source, byte **target, RSA *rsa)  {

	if (!rsa)
		return -1;

	int enc_size = RSA_size(rsa);

	if (!source || enc_size >= strlen(source))
		return -2;

	if (!target)
		return -3;

	byte *enc_buffer = NULL;
	int elen = base64_decode(source, &enc_buffer);
	if (elen != enc_size) {
		if (elen > 0)
			free(enc_buffer);
		return -4;
	}

	reallocate(target, elen - 11);

	elen = RSA_private_decrypt(elen, enc_buffer, *target, rsa, RSA_PKCS1_PADDING);

	free(enc_buffer);

	return elen > 0 ? elen : -5;

}

int __stdcall public_encrypt_b64(int slen, byte *source, byte **target, RSA *rsa)  {
	return public_encrypt_base64_buffer(slen, source, target, rsa);
}

int __stdcall public_decrypt_b64(byte *source, byte **target, RSA *rsa)  {
	return public_decrypt_base64_buffer(source, target, rsa);
}

int __stdcall private_encrypt_b64(int slen, byte *source, byte **target, RSA *rsa)  {
	return private_encrypt_base64_buffer(slen, source, target, rsa);
}

int __stdcall private_decrypt_b64(byte *source, byte **target, RSA *rsa)  {
	return private_decrypt_base64_buffer(source, target, rsa);
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

RSA *rsa_generate_key() {
        int rc;
        RSA* rsa;
        BIGNUM* e;

        rsa = RSA_new();
        if (!rsa) {
                print_last_error();
                return NULL;
        }

        e = BN_new();
        BN_set_word(e, RSA_F4);
        rc = RSA_generate_key_ex(rsa, 2048, e, NULL);
        BN_free(e);

        if (!rc) {
                print_last_error();
                return NULL;
        }

        return rsa;

}

RSA *__stdcall rsa_public_key_read_from_file(byte *fname) {
    struct stat filestat;
    RSA* rsa;
    int rc;

    rc = stat(fname, &filestat);
    if (rc)
    		return NULL;

    rsa = publickey_read_from_file(fname);

    return rsa;
}

RSA *__stdcall rsa_public_key_load_from_file(byte *fname) {
    struct stat filestat;
    RSA* rsa;
    int rc;

    rc = stat(fname, &filestat);
    if (rc) {

		rsa = rsa_generate_key();
		if (!rsa)
			privatekey_write_to_file(fname, rsa, u);
		else
			print_last_error();

    }
	else {
		rsa = publickey_read_from_file(fname);
    }

    return rsa;
}

RSA *__stdcall rsa_private_key_read_from_file(byte *fname) {
    struct stat filestat;
    RSA* rsa;
    int rc;

    rc = stat(fname, &filestat);
    if (rc)
			return NULL;

    rsa = privatekey_read_from_file(fname, u);

    return rsa;
}

RSA *__stdcall rsa_private_key_load_from_file(byte *fname) {
    struct stat filestat;
    RSA* rsa;
    int rc;

    rc = stat(fname, &filestat);
    if (rc) {

		rsa = rsa_generate_key();
		if (!rsa)
			privatekey_write_to_file(fname, rsa, u);
         else
			print_last_error();

    }
	else {
		rsa = privatekey_read_from_file(fname, u);
    }

    return rsa;
}

