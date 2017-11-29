#include "ossllib.h"
#include <sys/stat.h>

int public_encrypt_base64_buffer(int slen, unsigned char *source, 
                                unsigned char **target, RSA *rsa) {

	if (!rsa)
		exit_on_error(ERSAFAIL);

	int enc_size = RSA_size(rsa);

	if (!source || !target || slen >= enc_size - 11)
		exit_on_error(ERSAFAIL);

	unsigned char *enc_buffer = malloc(enc_size);
	memset(enc_buffer, 0, enc_size);

	int elen;
	elen = RSA_CRYPT(public, encrypt, slen, source, enc_buffer, rsa);

	if (elen < enc_size) {
		free(enc_buffer);
		exit_on_error(ERSAFAIL);
	}

	unsigned char *b64 = base64_encode(enc_buffer, elen, target);

	free(enc_buffer);

	return strlen((const char *)b64);

}

int private_encrypt_base64_buffer(int slen, unsigned char *source, 
                                unsigned char **target, RSA *rsa) {

	if (!rsa)
		exit_on_error(ERSAFAIL);

	int enc_size = RSA_size(rsa);

	if (!source || !target || slen >= enc_size - 11)
		exit_on_error(ERSAFAIL);

	unsigned char *enc_buffer = malloc(enc_size);
	memset(enc_buffer, 0, enc_size);

	int elen;
	elen = RSA_CRYPT(private, encrypt, slen, source, enc_buffer, rsa);

	if (elen < enc_size) {
		free(enc_buffer);
		exit_on_error(ERSAFAIL);
	}

	unsigned char *b64 = base64_encode(enc_buffer, elen, target);

	free(enc_buffer);

	return strlen((const char *)b64);

}

int public_decrypt_base64_buffer(unsigned char *source, 
                                unsigned char **target, RSA *rsa)  {

	if (!rsa)
	        exit_on_error(ERSAFAIL);

	int enc_size = RSA_size(rsa);

	if (!source || enc_size >= strlen((const char *)source))
	        exit_on_error(ERSAFAIL);

	if (!target)
	        exit_on_error(ERSAFAIL);

	unsigned char *enc_buffer = NULL;
	int elen = base64_decode(source, &enc_buffer);
	if (elen != enc_size) {
		if (elen > 0)
			free(enc_buffer);
		exit_on_error(ERSAFAIL);
	}

	reallocate(target, elen - 11);

	elen = RSA_CRYPT(public, decrypt, elen, enc_buffer, *target, rsa);

	free(enc_buffer);

	if (elen < 1)
	        exit_on_error(ERSAFAIL);

	return elen;

}

int private_decrypt_base64_buffer(unsigned char *source, 
                                unsigned char **target, RSA *rsa)  {

	if (!rsa)
	        exit_on_error(ERSAFAIL);

	int enc_size = RSA_size(rsa);

	if (!source || enc_size >= strlen((const char *)source))
	        exit_on_error(ERSAFAIL);

	if (!target)
	        exit_on_error(ERSAFAIL);

	unsigned char *enc_buffer = NULL;
	int elen = base64_decode(source, &enc_buffer);
	if (elen != enc_size) {
		if (elen > 0)
			free(enc_buffer);
		exit_on_error(ERSAFAIL);
	}

	reallocate(target, elen - 11);

	elen = RSA_CRYPT(private, decrypt, elen, enc_buffer, *target, rsa);

	free(enc_buffer);

	if (elen < 1)
	        exit_on_error(ERSAFAIL);

	return elen;

}

RSA *rsa_generate_key() {
        int rc;
        RSA* rsa;
        BIGNUM* e;

        rsa = RSA_new();
        if (!rsa) 
                exit_on_error(ERSAFAIL);

        e = BN_new();
        BN_set_word(e, RSA_F4);
        rc = RSA_generate_key_ex(rsa, 2048, e, NULL);
        BN_free(e);

        if (!rc) 
                exit_on_error(ERSAFAIL); 

        return rsa;

}

RSA *rsa_reset_key_files(const char *pri_pem, const char *pub_pem) {

        RSA *rsa = rsa_generate_key();
        publickey_write_to_file(pub_pem, rsa);
        privatekey_write_to_file(pri_pem, rsa);
        return rsa;
        
} 

RSA *rsa_publickey_read_from_file(const char *fname) {
        struct stat filestat;

        if (stat(fname, &filestat))
                exit_on_error(ERSARDFL);

        return publickey_read_from_file(fname);
}

RSA *rsa_publickey_load_from_file(const char *fname) {
        struct stat filestat;

        if (stat(fname, &filestat)) {

                RSA* rsa = rsa_generate_key();
                publickey_write_to_file(fname, rsa);
                return rsa;

        }

        return publickey_read_from_file(fname);

}

RSA *rsa_privatekey_read_from_file(const char *fname) {
        struct stat filestat;

        if (stat(fname, &filestat))
                exit_on_error(ERSARDFL);

        return privatekey_read_from_file(fname);
}

RSA *rsa_privatekey_load_from_file(const char *fname) {
        struct stat filestat;

        if (stat(fname, &filestat)) {

                RSA* rsa = rsa_generate_key();
                privatekey_write_to_file(fname, rsa);
                return rsa;

        }

        return privatekey_read_from_file(fname);

}

