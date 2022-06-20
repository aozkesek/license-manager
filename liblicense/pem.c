#include "ossllib.h"

const char u[] = { 1, 2, 3, 5, 8, 13, 21, 34, 0 };

void save_pubkey(const char *fname, RSA *rsa) {

        BIO* bp = BIO_new_file(fname, "w+");
        if (bp) {
                int rc = PEM_write_bio_RSAPublicKey(bp, rsa);
                BIO_free(bp);
                if (rc != 1) 
                        on_error(EPEMWRFL);
        }
        else 
                on_error(EPEMFAIL);
}

RSA *load_pubkey(const char *fname) {

        BIO* bp = BIO_new_file(fname, "r");
        if (bp) {
                RSA* rc = PEM_read_bio_RSAPublicKey(bp, NULL, NULL, NULL);
                BIO_free(bp);
                if (!rc) 
                        on_error(EPEMRDFL);
                return rc;
        }
        else 
                on_error(EPEMFAIL);

        return NULL;
}

void save_prikey(const char *fname, RSA* rsa) {

        BIO* bp = BIO_new_file(fname, "w+");
        if (bp) {
                int rc = PEM_write_bio_RSAPrivateKey(bp, rsa, NULL, NULL, 0, NULL, (void *)u);
                BIO_free(bp);
                if (rc != 1) 
                        on_error(EPEMWRFL);
        }
        else 
                on_error(EPEMFAIL);
}

RSA *load_prikey(const char *fname) {

        BIO* bp = BIO_new_file(fname, "r");
        if (bp) {
                RSA* rc = PEM_read_bio_RSAPrivateKey(bp, NULL, NULL, (void *)u);
                BIO_free(bp);
                if (!rc) 
                        on_error(EPEMRDFL);
                return rc;
        }
        else
                on_error(EPEMFAIL);

        return NULL;
}

