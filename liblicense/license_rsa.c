#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <memory.h>
#include <string.h>

#include "license.h"

extern const byte b64[];

const byte u[] =
	{ 1, 2, 3, 5, 8, 13, 21, 34, 0 };

void __stdcall publickey_write_to_file(const char *fileName, RSA* rsa) {

        BIO* bp = BIO_new_file(fileName, "w+");
        if (bp) {
                int rc = PEM_write_bio_RSAPublicKey(bp, rsa);
                BIO_free(bp);
                if (rc != 1) {
                        print_last_error();
                        exit_on_error();
                }
        }
        else {
                print_last_error();
                exit_on_error();
        }
}

RSA *__stdcall publickey_read_from_file(const char *fileName) {

        BIO* bp = BIO_new_file(fileName, "r");
        if (bp) {
                RSA* rc = PEM_read_bio_RSAPublicKey(bp, NULL, NULL, NULL);
                BIO_free(bp);
                if (!rc) {
                        print_last_error();
                        exit_on_error();
                }

                return rc;
        }
        else {
                print_last_error();
                exit_on_error();
        }

        return NULL;
}

void __stdcall privatekey_write_to_file(const char *fileName, RSA* rsa, const byte *u) {

        BIO* bp = BIO_new_file(fileName, "w+");
        if (bp) {
                int rc = PEM_write_bio_RSAPrivateKey(bp, rsa, NULL, NULL, 0, NULL, (void *)u);
                BIO_free(bp);
                if (rc != 1) {
                        print_last_error();
                        exit_on_error();
                }
        }
        else {
                print_last_error();
                exit_on_error();
        }
}

RSA *__stdcall privatekey_read_from_file(const char *fileName, const byte *u) {

        BIO* bp = BIO_new_file(fileName, "r");
        if (bp) {
                RSA* rc = PEM_read_bio_RSAPrivateKey(bp, NULL, NULL, (void *)u);
                BIO_free(bp);
                if (!rc) {
                        print_last_error();
                        exit_on_error();
                }

                return rc;
        }
        else {
                print_last_error();
                exit_on_error();
        }

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
		exit_on_error();

	int enc_size = RSA_size(rsa);

	if (!source || !target || slen >= enc_size - 11)
		exit_on_error();

	byte *enc_buffer = malloc(enc_size);
	memset(enc_buffer, 0, enc_size);

	int elen;
	elen = RSA_public_encrypt(slen, source, enc_buffer, rsa, RSA_PKCS1_PADDING);

	if (elen < enc_size) {
		free(enc_buffer);
		exit_on_error();
	}

	byte *b64 = base64_encode(enc_buffer, elen, target);

	free(enc_buffer);

	if (!b64)
		exit_on_error();

	return strlen((const char *)b64);

}

int private_encrypt_base64_buffer(int slen, byte *source, byte **target, RSA *rsa) {

	if (!rsa)
		exit_on_error();

	int enc_size = RSA_size(rsa);

	if (!source || !target || slen >= enc_size - 11)
		exit_on_error();

	byte *enc_buffer = malloc(enc_size);
	memset(enc_buffer, 0, enc_size);

	int elen;
	elen = RSA_private_encrypt(slen, source, enc_buffer, rsa, RSA_PKCS1_PADDING);

	if (elen < enc_size) {
		free(enc_buffer);
		exit_on_error();
	}

	byte *b64 = base64_encode(enc_buffer, elen, target);

	free(enc_buffer);

	if (!b64)
	        exit_on_error();

	return strlen((const char *)b64);

}

int public_decrypt_base64_buffer(byte *source, byte **target, RSA *rsa)  {

	if (!rsa)
	        exit_on_error();

	int enc_size = RSA_size(rsa);

	if (!source || enc_size >= strlen((const char *)source))
	        exit_on_error();

	if (!target)
	        exit_on_error();

	byte *enc_buffer = NULL;
	int elen = base64_decode(source, &enc_buffer);
	if (elen != enc_size) {
		if (elen > 0)
			free(enc_buffer);
		exit_on_error();
	}

	reallocate(target, elen - 11);

	elen = RSA_public_decrypt(elen, enc_buffer, *target, rsa, RSA_PKCS1_PADDING);

	free(enc_buffer);

	if (elen < 1)
	        exit_on_error();

	return elen;

}

int private_decrypt_base64_buffer(byte *source, byte **target, RSA *rsa)  {

	if (!rsa)
	        exit_on_error();

	int enc_size = RSA_size(rsa);

	if (!source || enc_size >= strlen((const char *)source))
	        exit_on_error();

	if (!target)
	        exit_on_error();

	byte *enc_buffer = NULL;
	int elen = base64_decode(source, &enc_buffer);
	if (elen != enc_size) {
		if (elen > 0)
			free(enc_buffer);
		exit_on_error();
	}

	reallocate(target, elen - 11);

	elen = RSA_private_decrypt(elen, enc_buffer, *target, rsa, RSA_PKCS1_PADDING);

	free(enc_buffer);

	if (elen < 1)
	        exit_on_error();

	return elen;

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
	        exit_on_error();

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

RSA *rsa_generate_key() {
        int rc;
        RSA* rsa;
        BIGNUM* e;

        rsa = RSA_new();
        if (!rsa) {
                print_last_error();
                exit_on_error();
        }

        e = BN_new();
        BN_set_word(e, RSA_F4);
        rc = RSA_generate_key_ex(rsa, 2048, e, NULL);
        BN_free(e);

        if (!rc) {
                print_last_error();
                exit_on_error();
        }

        return rsa;

}

RSA *__stdcall rsa_publickey_read_from_file(const char *fname) {
        struct stat filestat;

        if (stat(fname, &filestat))
                exit_on_error();

        return publickey_read_from_file(fname);
}

RSA *__stdcall rsa_publickey_load_from_file(const char *fname) {
        struct stat filestat;

        if (stat(fname, &filestat)) {

                RSA* rsa = rsa_generate_key();
                if (!rsa) {
                        print_last_error();
                        exit_on_error();
                }

                privatekey_write_to_file(fname, rsa, u);
                return rsa;

        }

        return publickey_read_from_file(fname);

}

RSA *__stdcall rsa_privatekey_read_from_file(const char *fname) {
        struct stat filestat;

        if (stat(fname, &filestat))
                exit_on_error();

        return privatekey_read_from_file(fname, u);
}

RSA *__stdcall rsa_privatekey_load_from_file(const char *fname) {
        struct stat filestat;

        if (stat(fname, &filestat)) {

                RSA* rsa = rsa_generate_key();
                if (!rsa) {
                        print_last_error();
                        exit_on_error();
                }

                privatekey_write_to_file(fname, rsa, u);
                return rsa;

        }

        return privatekey_read_from_file(fname, u);

}

