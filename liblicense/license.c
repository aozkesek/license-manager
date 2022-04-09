#include "license.h"

#ifdef DEBUG
const char *provider_pem = "tmp-provider.pem";
const char *provider_pub_pem = "tmp-provider-pub.pem";
const char *customer_pem = "tmp-customer.pem";
const char *customer_pub_pem = "tmp-customer-pub.pem";
const char *customer_lic = "tmp-customer.lic";
const char *customer_license = "tmp-customer.license";
#else
const char *provider_pem = "provider.pem";
const char *provider_pub_pem = "provider-pub.pem";
const char *customer_pem = "customer.pem";
const char *customer_pub_pem = "customer-pub.pem";
const char *customer_lic = "customer.lic";
const char *customer_license = "customer.license";
#endif

const char *begin_session = "-----BEGIN SESSION KEY-----";
const char *begin_session_ex = "-----BEGIN SESSION KEY-----\n";
const char *end_session = "-----END SESSION KEY-----";
const char *end_session_ex = "-----END SESSION KEY-----\n";
const char *begin_customer_pub = "-----BEGIN RSA PUBLIC KEY-----";
const char *begin_customer_pub_ex = "-----BEGIN RSA PUBLIC KEY-----\n";
const char *end_customer_pub = "-----END RSA PUBLIC KEY-----";
const char *end_customer_pub_ex = "-----END RSA PUBLIC KEY-----\n";
const char *begin_license = "-----BEGIN LICENSE-----";
const char *begin_license_ex = "-----BEGIN LICENSE-----\n";
const char *end_license = "-----END LICENSE-----";
const char *end_license_ex = "-----END LICENSE-----\n";
const char *begin_sha_a = "-----BEGIN SHA1 A-----";
const char *begin_sha_a_ex = "-----BEGIN SHA1 A-----\n";
const char *end_sha_a = "-----END SHA1 A-----";
const char *end_sha_a_ex = "-----END SHA1 A-----\n";
const char *begin_sha_b = "-----BEGIN SHA1 B-----";
const char *begin_sha_b_ex = "-----BEGIN SHA1 B-----\n";
const char *end_sha_b = "-----END SHA1 B-----";
const char *end_sha_b_ex = "-----END SHA1 B-----\n";

void (*onerror)(int) = NULL;

void exit_on_error(const char *fname, const char *fn_name, int line, int error) 
{
        printf("vvv program is stopped on error: %d vvv\n(%s:%d::%s)\n",
                error, fname, line, fn_name);
        
        if (onerror)
                onerror(error);
}

char *ext_subval_ex(const char *src, const char *tbegin, const char *tend)
{

        char *p_tbegin = strstr(src, tbegin);
        if (!p_tbegin)
                on_error(-EEXTRAC);

        char *p_tend = strstr(src, tend);
        if (!p_tend)
                on_error(-EEXTRAC);

        int i = 0, j = 0;
        int pos = strlen(tbegin);
        int len = p_tend - p_tbegin - pos;
        char *key = malloc(len + 1);
        memset(key, 0, len + 1);
        while (i < len) {
                if (p_tbegin[pos + i] != '\n')
                        key[j++] = p_tbegin[pos + i];
                i++;
        }

        return key;

}

char *ext_subval(const char *src, const char *tbegin, const char *tend)
{
 
        char *p_tbegin = strstr(src, tbegin);
        if (!p_tbegin)
                on_error(-EEXTRAC);

        char *p_tend = strstr(src, tend);
        if (!p_tend)
                on_error(-EEXTRAC);

        int i = 0, j = 0;
        int pos = strlen(tbegin);
        int len = p_tend - p_tbegin - pos;
        char *key = malloc(len + 1);
        memset(key, 0, len + 1);
        while (i < len)
                key[j++] = p_tbegin[pos + i++];

        return key;

}

char *digest(const char *src, const int srclen, char **outb)
{
	
        unsigned int md_len = 0;
        EVP_MD_CTX *mdctx;
        const EVP_MD *md;
        char sha_buffer[EVP_MAX_MD_SIZE];
         
        if (!src || !outb || srclen < 1)
	        on_error(ESHAFAIL);

        md = EVP_get_digestbyname("blake2s256");
        if(!md) 
                on_error(ESHAFAIL);

        mdctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(mdctx, md, NULL);
        EVP_DigestUpdate(mdctx, src, srclen);
        EVP_DigestFinal_ex(mdctx, sha_buffer, &md_len);
        EVP_MD_CTX_free(mdctx);
 
	return base64_encode(sha_buffer, md_len, outb);
}

int load_from_file(const char *fname, char **outb) {
 
        if (!outb)
                on_error(-ERDFILE);
                
        FILE *file = fopen(fname, "r");
        if (!file)
                on_error(-ERDFILE);
 
        if (fseek(file, 0, SEEK_END)) {
                fclose(file);
                on_error(-ERDFILE);
        }

        int flen = ftell(file);
        rewind(file);

        reallocate(outb, flen + 1); 
        fread(*outb, flen, 1, file); 
        fclose(file);
 
        (*outb)[flen] = 0;
 
        return flen;
}

/**
 * only the customer's part can call this,
 * provider's public key needed.
 */
void verify_license()
{
	char *lic_buff = NULL;
	char *sha_buff = NULL;
	int len = 0;
	
	load_from_file(customer_license, &lic_buff);
	
	while (lic_buff[len] != '\n') len++;
	digest(lic_buff, len, &sha_buff);
	
	char *enc_sha_a = ext_subval_ex(lic_buff, begin_sha_a_ex, end_sha_a_ex);
	char *enc_sha_b = ext_subval_ex(lic_buff, begin_sha_b_ex, end_sha_b_ex);
	
	char *sha_a = NULL;
	char *sha_b = NULL;
	RSA *rsa = get_prikey(customer_pem);
	
	int len_a = pri_decrypt(enc_sha_a, &sha_a, rsa);
	int len_b = pri_decrypt(enc_sha_b, &sha_b, rsa);
	char *enc_sha = NULL;
	char *sha = NULL;
	reallocate(&enc_sha, len_a + len_b + 1);
	memcpy(enc_sha, sha_a, len_a);
	memcpy(enc_sha+len_a, sha_b, len_b);
	rsa = get_pubkey(provider_pub_pem);
	len = pub_decrypt(enc_sha, &sha, rsa);
	
	if (strcmp(sha_buff, sha))
		on_error(ELICFAIL);

}

void license_app(const char *app_version) 
{

        if (!app_version)
                on_error(ELICFAIL);

        char *client_licence_buffer = NULL;
        char license[128];

        load_from_file(customer_license, &client_licence_buffer);
        sprintf(license, ",\"Version\":\"%s\",", app_version);
        if (!strstr(client_licence_buffer, license))
                on_error(ELICFAIL);

}

void license_service(const char *app_version, const char *svc_name, const char *svc_version) 
{

        if (!app_version || !svc_name || !svc_version)
                on_error(ELICFAIL);

        char *client_licence_buffer = NULL;
        char license[128];

        load_from_file(customer_license, &client_licence_buffer);
        sprintf(license, ",\"Version\":\"%s\",", app_version);
        if (!strstr(client_licence_buffer, license))
                on_error(ELICFAIL);
        sprintf(license, "{\"Name\":\"%s\",\"Version\":\"%s\"}", 
                svc_name, svc_version);
        if (!strstr(client_licence_buffer, license))
                on_error(ELICFAIL);
        

}

