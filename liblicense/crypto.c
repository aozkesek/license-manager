#include "ossllib.h"

#define crypto_check(ctx,s,sz,pt,k) (ctx && s && sz && pt && k)

void crypto_init(void (*on_err)(int))
{       
        onerror = on_err;
        if (!OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, NULL))
                onerror(-1);
        
}

void cleanup_on_error(EVP_CIPHER_CTX *ctx, int error_code) 
{
        if (ctx) 
                EVP_CIPHER_CTX_free(ctx);
        
        on_error(error_code);
}

int encrypt(const char *src, int srclen, char **target, const char *session_key)
{

        EVP_CIPHER_CTX *ctx= EVP_CIPHER_CTX_new();
        if (!crypto_check(ctx, src, srclen, target, session_key))
                cleanup_on_error(ctx, EENCFAIL);

        int tlen, flen;
        
        if (!EVP_EncryptInit_ex(ctx, EVP_bf_cbc(), NULL, session_key, NULL))
                cleanup_on_error(ctx, EENCINIT);
        
        tlen = srclen % EVP_CIPHER_block_size((const EVP_CIPHER *)ctx) + srclen + 1;
        reallocate(target, tlen + 1);

        if (!EVP_EncryptUpdate(ctx, *target, &tlen, src, srclen))
                cleanup_on_error(ctx, EENCUPDT);

        if (!EVP_EncryptFinal_ex(ctx, *target + tlen, &flen))
                cleanup_on_error(ctx, EENCFINL);

        tlen += flen;

        EVP_CIPHER_CTX_free(ctx);

        return tlen;
}

int decrypt(const char *src, int srclen, char **target, const char *session_key)
{

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

        if (!crypto_check(ctx, src, srclen, target, session_key))
                cleanup_on_error(ctx, EDECFAIL);

        int tlen, flen;
        
        if (!EVP_DecryptInit_ex(ctx, EVP_bf_cbc(), NULL, session_key, NULL))
                cleanup_on_error(ctx, EDECINIT);

        tlen = srclen % EVP_CIPHER_block_size((const EVP_CIPHER *)ctx) + 
                srclen + 1;
        reallocate(target, tlen + 1);

        if (!EVP_DecryptUpdate(ctx, *target, &tlen, src, srclen))
                cleanup_on_error(ctx, EDECUPDT);
                
        if (!EVP_DecryptFinal_ex(ctx, *target + tlen, &flen))
                cleanup_on_error(ctx, EDECFINL);

        tlen += flen;

        EVP_CIPHER_CTX_free(ctx);

        memset(*target + tlen, 0, 1);

        return tlen;
}
