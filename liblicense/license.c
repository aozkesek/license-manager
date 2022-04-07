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
const char *begin_license_sha_a = "-----BEGIN SHA1 A-----";
const char *begin_license_sha_a_ex = "-----BEGIN SHA1 A-----\n";
const char *end_license_sha_a = "-----END SHA1 A-----";
const char *end_license_sha_a_ex = "-----END SHA1 A-----\n";
const char *begin_license_sha_b = "-----BEGIN SHA1 B-----";
const char *begin_license_sha_b_ex = "-----BEGIN SHA1 B-----\n";
const char *end_license_sha_b = "-----END SHA1 B-----";
const char *end_license_sha_b_ex = "-----END SHA1 B-----\n";

void (*onerror)(int) = NULL;

void exit_on_error(const char *fname, const char *fn_name, int line, int error) 
{
        printf("vvv program is stopped on error: %d vvv\n(%s:%d::%s)\n",
                error, fname, line, fn_name);
        
        if (onerror)
                onerror(error);
}

char *digest(const char *src, const int srclen, char **target)
{
	
        unsigned int md_len = 0;
        EVP_MD_CTX *mdctx;
        const EVP_MD *md;
        char sha_buffer[EVP_MAX_MD_SIZE];
         
        if (!src || !target || srclen < 1)
	        on_error(ESHAFAIL);

        md = EVP_get_digestbyname("blake2s256");

        if(!md) 
                on_error(ESHAFAIL);

        mdctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(mdctx, md, NULL);
        EVP_DigestUpdate(mdctx, src, srclen);
        EVP_DigestFinal_ex(mdctx, sha_buffer, &md_len);
        EVP_MD_CTX_free(mdctx);
 
	return base64_encode(sha_buffer, md_len, target);
}

int load_from_file(const char *fname, char **buffer) {
 
        if (!buffer)
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

        reallocate(buffer, flen + 1); 
        fread(*buffer, flen, 1, file); 
        fclose(file);
 
        (*buffer)[flen] = 0;
 
        return flen;
}

void sha_initialize(struct sha *sha) {

	if (!sha)
		on_error(ELICINIT);

	memset(sha, 0, sizeof(struct sha));

	sha->pub_provider = get_pubkey(provider_pub_pem);
	sha->pri_client = get_prikey(customer_pem);

}

void sha_finalize(struct sha *sha) {

	if (!sha)
	        on_error(ELICFINL);

	if (sha->src_sha) 
                free(sha->src_sha);
	if (sha->sha) 
                free(sha->sha);

	if (sha->pub_provider) 
                RSA_free(sha->pub_provider);
	if (sha->pri_client) 
                RSA_free(sha->pri_client);


}

void decrypt_sha(struct sha *sha, char *sha_a, char *sha_b)
{

	if (!sha)
		on_error(ELICUPDT);

	char *dec_shaa = NULL;
	int alen = pri_decrypt(sha_a, &dec_shaa, sha->pri_client);
	
	char *dec_shab = NULL;
	int blen = pri_decrypt(sha_b, &dec_shab, sha->pri_client);

	char *temp = malloc(alen + blen + 1);
	memset(temp, 0, alen + blen + 1);
	memcpy(temp, dec_shaa, alen);
	memcpy(temp + alen, dec_shab, blen);

	free(dec_shaa);
	free(dec_shab);

	pub_decrypt(temp, &sha->sha, sha->pub_provider);
	free(temp);

}

void build_sha(char *src, char *sha_a, char *sha_b)
{

	if (!src || !sha_a || !sha_b)
		on_error(ESHAFAIL);

	struct sha sha;
        sha_initialize(&sha);

	sha.src_sha = NULL;
	digest(src, strlen(src), &sha.src_sha);
	
	decrypt_sha(&sha, sha_a, sha_b);
        
 	int result = strcmp(sha.src_sha, sha.sha);
         
	sha_finalize(&sha);

	if (result != 0)
                on_error(ESHAFAIL);

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

void license_selftest()
{
        char *seskey = NULL;
        char *hashed = NULL;

        printf("testing digest with blake2s256...\n");
        gen_session_key(196, &seskey);
        digest(seskey, strlen(seskey), &hashed);
        printf("input %d %s\nhashed:b64 %d %s\n", 
                strlen(seskey), seskey, strlen(hashed), hashed);

        char *tmpcuspri = "tmp-customer.pem";
        char *tmppropri = "tmp-provider.pem";
        char *tmpcuspub = "tmp-customer-pub.pem";
        char *tmppropub = "tmp-provider-pub.pem";

        RSA *cust = get_prikey_ex(tmpcuspri);
        save_pubkey(tmpcuspub, cust);
        RSA *prov = get_prikey_ex(tmppropri);
        save_pubkey(tmppropub, prov);

        if (cust) {
                printf("customer's key test passed.\n");
        }

        if (prov) {
                printf("provider's key test passed.\n");       
        }

cleanup:
        free(seskey);
        free(hashed);

}
