#include "ossllib.h"

void crypto_init() 
{       

        if (!OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, NULL))
                exit_on_error(-1);
        
}

void crypto_final() 
{
        OPENSSL_cleanup();
}

static inline void reallocate(unsigned char **p, int s) 
{
        if (!p) return;         //consider to throw exception
        if (*p) free(*p);
        *p = malloc(s);
        memset(*p, 0, s);
}

void cleanup_on_error(EVP_CIPHER_CTX *ctx, int error_code) 
{
        
        if (ctx) 
                EVP_CIPHER_CTX_free(ctx);
        
        exit_on_error(error_code);
}


static inline int crypto_check(EVP_CIPHER_CTX *ctx, 
                                const unsigned char *source, int slen, 
                                unsigned char **target, 
                                const unsigned char *session_key) 
{
        
        if (!ctx)
                return 0;
                
        if (!source || !slen)
		return 0;
        // we do not care the inner value of the target, but it's address
	if (!target)
		return 0;

	if (!session_key)
		return 0;

        return 1;
}

int encrypt(const unsigned char *source, int slen, unsigned char **target, 
                const unsigned char *session_key) 
{

        EVP_CIPHER_CTX *ctx= EVP_CIPHER_CTX_new();
        if (!crypto_check(ctx, source, slen, target, session_key))
                cleanup_on_error(ctx, EENCFAIL);

        int tlen, flen;
        
        if (!EVP_EncryptInit_ex(ctx, EVP_bf_cbc(), NULL, session_key, NULL))
                cleanup_on_error(ctx, EENCINIT);
        
        tlen = slen % EVP_CIPHER_block_size((const EVP_CIPHER *)ctx) +
                slen + 1;
        reallocate(target, tlen + 1);

        if (!EVP_EncryptUpdate(ctx, *target, &tlen, source, slen))
                cleanup_on_error(ctx, EENCUPDT);

        if (!EVP_EncryptFinal_ex(ctx, *target + tlen, &flen))
                cleanup_on_error(ctx, EENCFINL);

        tlen += flen;

        EVP_CIPHER_CTX_free(ctx);

        return tlen;
}

int decrypt(const unsigned char *source, int slen, unsigned char **target, 
                const unsigned char *session_key) 
{

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

        if (!crypto_check(ctx, source, slen, target, session_key))
                cleanup_on_error(ctx, EDECFAIL);

        int tlen, flen;
        
        if (!EVP_DecryptInit_ex(ctx, EVP_bf_cbc(), NULL, session_key, NULL))
                cleanup_on_error(ctx, EDECINIT);

        tlen = slen % EVP_CIPHER_block_size((const EVP_CIPHER *)ctx) + 
                slen + 1;
        reallocate(target, tlen + 1);

        if (!EVP_DecryptUpdate(ctx, *target, &tlen, source, slen))
                cleanup_on_error(ctx, EDECUPDT);
                
        if (!EVP_DecryptFinal_ex(ctx, *target + tlen, &flen))
                cleanup_on_error(ctx, EDECFINL);

        tlen += flen;

        EVP_CIPHER_CTX_free(ctx);

        memset(*target + tlen, 0, 1);

        return tlen;
}
