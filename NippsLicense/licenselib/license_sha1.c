#include <string.h>
#include <stdlib.h>
#include <memory.h>

#include "license.h"

typedef struct _LICENSESHA1 {
	RSA *pub_netas;
	RSA *pri_client;

	byte *source_sha1;
	byte *sha1;

} LICENSESHA1, *PLICENSESHA1;

byte *__stdcall sha1(byte *source, int slen, byte **target) {
	byte sha1_buffer[SHA_DIGEST_LENGTH];
	if (!source || !target || slen < 1)
		return NULL;

	if (!SHA1(source, slen, sha1_buffer))
		return NULL;

	return encode_b64(sha1_buffer, SHA_DIGEST_LENGTH, target);
}

int license_sha1_initialize(PLICENSESHA1 plsha1, byte *pem_path) {

	if (!plsha1)
		return 1;

	memset(plsha1, 0, sizeof(LICENSESHA1));
	
	byte pemName[_MAX_PATH];
	memset(pemName, 0, _MAX_PATH);
	sprintf(pemName, "%s\\pub_netas.pem", pem_path);

	plsha1->pub_netas = load_key(pemName, false, true);
	if (!plsha1->pub_netas)
		return 1;
	
	memset(pemName, 0, _MAX_PATH);
	sprintf(pemName, "%s\\pri_client.pem", pem_path);

	plsha1->pri_client = load_key(pemName, false, false);
	if (!plsha1->pri_client)
		return 1;

	return 0;
}

void license_sha1_finalize(PLICENSESHA1 plsha1) {

	if (!plsha1) return;

	if (plsha1->source_sha1) free(plsha1->source_sha1);
	if (plsha1->sha1) free(plsha1->sha1);

	if (plsha1->pub_netas) RSA_free(plsha1->pub_netas);
	if (plsha1->pri_client) RSA_free(plsha1->pri_client);


}

int license_sha1_decrypt(PLICENSESHA1 plsha1, byte *sha1a, byte *sha1b) {

	if (!plsha1)
		return 1;

	byte *dec_sha1a = NULL;
	int alen = private_decrypt_b64(sha1a, &dec_sha1a, plsha1->pri_client);
	if (alen < 0) {
		print_last_error();
		return 1;
	}
	
	byte *dec_sha1b = NULL;
	int blen = private_decrypt_b64(sha1b, &dec_sha1b, plsha1->pri_client);
	if (blen < 0) {
		print_last_error();
		free(dec_sha1a);
		return 1;
	}
	
	byte *sha1 = malloc(alen + blen + 1);
	memset(sha1, 0, alen + blen + 1);
	memcpy(sha1, dec_sha1a, alen);
	memcpy(sha1 + alen, dec_sha1b, blen);

	free(dec_sha1a);
	free(dec_sha1b);

	alen = public_decrypt_b64(sha1, &plsha1->sha1, plsha1->pub_netas);
	free(sha1);

	if (alen < 0) {
		print_last_error();
		return 1;
	}
		
	return 0;
}


int __stdcall LicenseSha1(byte *pem_path, byte *source, byte *sha1a, byte *sha1b) {

	if (!source || !sha1a || !sha1b)
		return -1;

	LICENSESHA1 lsha1;
	byte decrypted_sha1[SHA_DIGEST_LENGTH];

	memset(decrypted_sha1, 0, SHA_DIGEST_LENGTH);

	if (license_sha1_initialize(&lsha1, pem_path))
		return -2;

	lsha1.source_sha1 = NULL;
	if (!sha1(source, strlen(source), &lsha1.source_sha1)) {
		license_sha1_finalize(&lsha1);
		return -3;
	}
	
	if (license_sha1_decrypt(&lsha1, sha1a, sha1b)) {
		license_sha1_finalize(&lsha1);
		return -4;
	}

	if (memcmp(lsha1.source_sha1, lsha1.sha1, SHA_DIGEST_LENGTH) != 0) {
		license_sha1_finalize(&lsha1);
		return 1;
	}

	license_sha1_finalize(&lsha1);

	return 0;
}

