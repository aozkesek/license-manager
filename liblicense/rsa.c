#include "ossllib.h"
#include <sys/stat.h>

int pub_encrypt(int srclen, char *src, char **target, RSA *rsa)
{

	if (!rsa)
		on_error(ERSAFAIL);

	int enc_size = RSA_size(rsa);

	if (!src || !target || srclen >= enc_size - 11)
		on_error(ERSAFAIL);

	char *enc_buffer = NULL;
	reallocate(&enc_buffer, enc_size);

	int elen;
	elen = RSA_CRYPT(public, encrypt, srclen, src, enc_buffer, rsa);

	if (elen < enc_size) {
		free(enc_buffer);
		on_error(ERSAFAIL);
	}

	char *b64 = base64_encode(enc_buffer, elen, target);

	free(enc_buffer);

	return strlen(b64);

}

int pri_encrypt(int srclen, char *src, char **target, RSA *rsa)
{

	if (!rsa)
		on_error(ERSAFAIL);

	int enc_size = RSA_size(rsa);

	if (!src || !target || srclen >= enc_size - 11)
		on_error(ERSAFAIL);

	char *enc_buffer = malloc(enc_size);
	memset(enc_buffer, 0, enc_size);

	int elen;
	elen = RSA_CRYPT(private, encrypt, srclen, src, enc_buffer, rsa);

	if (elen < enc_size) {
		free(enc_buffer);
		on_error(ERSAFAIL);
	}

	char *b64 = base64_encode(enc_buffer, elen, target);

	free(enc_buffer);

	return strlen(b64);

}

int pub_decrypt(char *src, char **target, RSA *rsa)
{

	if (!rsa)
	        on_error(ERSAFAIL);

	int enc_size = RSA_size(rsa);

	if (!src || enc_size >= strlen((const char *)src))
	        on_error(ERSAFAIL);

	if (!target)
	        on_error(ERSAFAIL);

	char *enc_buffer = NULL;
	int elen = base64_decode(src, strlen(src), &enc_buffer);
	if (elen != enc_size) {
		if (elen > 0)
			free(enc_buffer);
		on_error(ERSAFAIL);
	}

	reallocate(target, elen - 11);

	elen = RSA_CRYPT(public, decrypt, elen, enc_buffer, *target, rsa);

	free(enc_buffer);

	if (elen < 1)
	        on_error(ERSAFAIL);

	return elen;

}

int pri_decrypt(char *src, char **target, RSA *rsa)
{

	if (!rsa)
	        on_error(ERSAFAIL);

	int enc_size = RSA_size(rsa);

	if (!src || enc_size >= strlen((const char *)src))
	        on_error(ERSAFAIL);

	if (!target)
	        on_error(ERSAFAIL);

	char *enc_buffer = NULL;
	int elen = base64_decode(src, strlen(src), &enc_buffer);
	if (elen != enc_size) {
		if (elen > 0)
			free(enc_buffer);
		on_error(ERSAFAIL);
	}

	reallocate(target, elen - 11);

	elen = RSA_CRYPT(private, decrypt, elen, enc_buffer, *target, rsa);

	free(enc_buffer);

	if (elen < 1)
	        on_error(ERSAFAIL);

	return elen;

}

RSA *gen_key() 
{
        int rc;
        RSA* rsa;
        BIGNUM* e;

        rsa = RSA_new();
        if (!rsa) 
                on_error(ERSAFAIL);

        e = BN_new();
        BN_set_word(e, RSA_F4);
        rc = RSA_generate_key_ex(rsa, 2048, e, NULL);
        BN_free(e);

        if (!rc) 
                on_error(ERSAFAIL); 

        return rsa;

}

RSA *reset_key(const char *pri_pem, const char *pub_pem)
{

        RSA *rsa = gen_key();
        save_pubkey(pub_pem, rsa);
        save_prikey(pri_pem, rsa);
        return rsa;
        
} 

RSA *get_pubkey(const char *fname) 
{
        struct stat filestat;

        if (stat(fname, &filestat))
                on_error(ERSARDFL);

        return load_pubkey(fname);
}

RSA *get_pubkey_ex(const char *fname) 
{
        struct stat filestat;

        if (stat(fname, &filestat)) {

                RSA* rsa = gen_key();
                save_pubkey(fname, rsa);
                return rsa;

        }

        return load_pubkey(fname);

}

RSA *get_prikey(const char *fname) 
{
        struct stat filestat;

        if (stat(fname, &filestat))
                on_error(ERSARDFL);

        return load_prikey(fname);
}

RSA *get_prikey_ex(const char *fname) 
{
        struct stat filestat;

        if (stat(fname, &filestat)) {

                RSA* rsa = gen_key();
                save_prikey(fname, rsa);
                return rsa;

        }

        return load_prikey(fname);

}

void rsa_selftest()
{

}
