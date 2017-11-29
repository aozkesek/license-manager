#include "ossllib.h"

const unsigned char u[] = { 1, 2, 3, 5, 8, 13, 21, 34, 0 };

void publickey_write_to_file(const char *fileName, RSA *rsa) {

        BIO* bp = BIO_new_file(fileName, "w+");
        if (bp) {
                int rc = PEM_write_bio_RSAPublicKey(bp, rsa);
                BIO_free(bp);
                if (rc != 1) 
                        exit_on_error(EPEMWRFL);
        }
        else 
                exit_on_error(EPEMFAIL);
}

RSA *publickey_read_from_file(const char *fileName) {

        BIO* bp = BIO_new_file(fileName, "r");
        if (bp) {
                RSA* rc = PEM_read_bio_RSAPublicKey(bp, NULL, NULL, NULL);
                BIO_free(bp);
                if (!rc) 
                        exit_on_error(EPEMRDFL);
                return rc;
        }
        else 
                exit_on_error(EPEMFAIL);

        return NULL;
}

void privatekey_write_to_file(const char *fileName, RSA* rsa) {

        BIO* bp = BIO_new_file(fileName, "w+");
        if (bp) {
                int rc = PEM_write_bio_RSAPrivateKey(bp, rsa, NULL, NULL, 0, 
                                                        NULL, (void *)u);
                BIO_free(bp);
                if (rc != 1) 
                        exit_on_error(EPEMWRFL);
        }
        else 
                exit_on_error(EPEMFAIL);
}

RSA *privatekey_read_from_file(const char *fileName) {

        BIO* bp = BIO_new_file(fileName, "r");
        if (bp) {
                RSA* rc = PEM_read_bio_RSAPrivateKey(bp, NULL, NULL, 
                                                        (void *)u);
                BIO_free(bp);
                if (!rc) 
                        exit_on_error(EPEMRDFL);
                return rc;
        }
        else
                exit_on_error(EPEMFAIL);

        return NULL;
}
