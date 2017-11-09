#include <stdlib.h>
#include <string.h>

#include "license.h"

int __stdcall crypt(byte *source, int slen, byte **target, byte *session_key, crypto c) {
	EVP_CIPHER_CTX *ctx;
	int rc, tlen, flen;

	if (!source || !slen)
		return 0;

	if (!target)
		return 0;

	if (!session_key)
		return 0;

	ctx = EVP_CIPHER_CTX_new();

	rc = EVP_CipherInit_ex(ctx, EVP_bf_cbc(), NULL, session_key, NULL, c);
	if (!rc) {
		print_last_error();
                EVP_CIPHER_CTX_free(ctx);
		return 0;
	}

	tlen = slen + slen % EVP_CIPHER_block_size(ctx) + 1;
	reallocate(target, tlen + 1);

	if (c)
		rc = EVP_EncryptUpdate(ctx, *target, &tlen, source, slen);
	else
		rc = EVP_DecryptUpdate(ctx, *target, &tlen, source, slen);
	if (!rc) {
		print_last_error();
		EVP_CIPHER_CTX_free(ctx);
		return 0;
	}

	if (c)
		rc = EVP_EncryptFinal_ex(ctx, (*target) + tlen, &flen);
	else
		rc = EVP_DecryptFinal_ex(ctx, (*target) + tlen, &flen);
	if (!rc) {
		print_last_error();
		EVP_CIPHER_CTX_free(ctx);
		return 0;
	}

	tlen += flen;

	EVP_CIPHER_CTX_free(ctx);

	if (!c)
		memset((*target) + tlen, 0, 1);

	return tlen;
}
