#include "license.h"

const char *prov_pri_pem = "provider.pem";
const char *prov_pub_pem = "public_provider.pem";
const char *cli_pri_pem = "customer.pem";
const char *cli_pub_pem = "public_customer.pem";
const char *client_lic = "client.lic";
const char *client_license = "client.license";

const char *begin_session = "---BEGIN SESSION KEY---";
const char *end_session = "---END SESSION KEY---";
const char *begin_key = "---BEGIN RSA PRIVATE KEY---";
const char *end_key = "---END RSA PRIVATE KEY---";
const char *begin_license = "---BEGIN LICENSE---";
const char *end_license = "---END LICENSE---";
const char *begin_license_sha_a = "---BEGIN SHA1 A---";
const char *end_license_sha_a = "---END SHA1 A---";
const char *begin_license_sha_b = "---BEGIN SHA1 B---";
const char *end_license_sha_b = "---END SHA1 B---";

void exit_on_error_m(const char *filename, const char *function_name, 
                        int line_number, int error_code) {
        
        printf("vvv program is stopped on error: %d vvv\n(%s:%d::%s)\n",
                error_code, filename, line_number, function_name);
        
        program_exit(error_code);
}

unsigned char *sha256(const unsigned char *source, const int slen, 
                        unsigned char **target) {
	
        unsigned int md_len = 0;
        EVP_MD_CTX *mdctx;
        const EVP_MD *md;
        unsigned char sha_buffer[EVP_MAX_MD_SIZE];
         
        if (!source || !target || slen < 1)
	        exit_on_error(ESHAFAIL);

        md = EVP_get_digestbyname("SHA256");

        if(!md) exit_on_error(ESHAFAIL);

        mdctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(mdctx, md, NULL);
        EVP_DigestUpdate(mdctx, source, slen);
        EVP_DigestFinal_ex(mdctx, sha_buffer, &md_len);
        EVP_MD_CTX_free(mdctx);
 
	return base64_encode(sha_buffer, md_len, target);
}

int load_from_file(const char *fname, unsigned char **buffer) {
 
        if (!buffer)
                exit_on_error(-ERDFILE);
                
        FILE *file = fopen(fname, "r");
        if (!file)
                exit_on_error(-ERDFILE);
 
        if (fseek(file, 0, SEEK_END)) {
                fclose(file);
                exit_on_error(-ERDFILE);
        }

        int flen = ftell(file);
        rewind(file);

        reallocate(buffer, flen + 1); 
        fread(*buffer, flen, 1, file); 
        fclose(file);
 
        (*buffer)[flen] = 0;
 
        return flen;
}

void license_sha_initialize(PLICENSE_SHA_STRUCT plsha) {

	if (!plsha)
		exit_on_error(ELICINIT);

	memset(plsha, 0, sizeof(LICENSE_SHA_STRUCT));

	plsha->pub_provider = rsa_publickey_read_from_file(prov_pub_pem);
	plsha->pri_client = rsa_privatekey_read_from_file(cli_pri_pem);

}

void license_sha_finalize(PLICENSE_SHA_STRUCT plsha) {

	if (!plsha)
	        exit_on_error(ELICFINL);

	if (plsha->source_sha) free(plsha->source_sha);
	if (plsha->sha) free(plsha->sha);

	if (plsha->pub_provider) RSA_free(plsha->pub_provider);
	if (plsha->pri_client) RSA_free(plsha->pri_client);


}

void license_sha_decrypt(PLICENSE_SHA_STRUCT plsha, unsigned char *sha_a, 
                        unsigned char *sha_b) {

	if (!plsha)
		exit_on_error(ELICUPDT);

	unsigned char *dec_shaa = NULL;
	int alen = private_decrypt_base64_buffer(sha_a, &dec_shaa, 
                                                plsha->pri_client);
	
	unsigned char *dec_shab = NULL;
	int blen = private_decrypt_base64_buffer(sha_b, &dec_shab, 
                                                plsha->pri_client);

	unsigned char *sha = malloc(alen + blen + 1);
	memset(sha, 0, alen + blen + 1);
	memcpy(sha, dec_shaa, alen);
	memcpy(sha + alen, dec_shab, blen);

	free(dec_shaa);
	free(dec_shab);

	public_decrypt_base64_buffer(sha, &plsha->sha, plsha->pub_provider);
	free(sha);

}

void license_sha(unsigned char *source, unsigned char *sha_a, 
                unsigned char *sha_b) {

	if (!source || !sha_a || !sha_b)
		exit_on_error(ESHAFAIL);

	LICENSE_SHA_STRUCT lsha;
        license_sha_initialize(&lsha);

	lsha.source_sha = NULL;
	sha256(source, strlen((const char *)source), &lsha.source_sha);
	
	license_sha_decrypt(&lsha, sha_a, sha_b);
        
 	int result = strcmp(lsha.source_sha, lsha.sha);
         
	license_sha_finalize(&lsha);

	if (result != 0)
                exit_on_error(ESHAFAIL);

}

void license_for_app(const char *app_version) {

        if (!app_version)
                exit_on_error(ELICFAIL);

        unsigned char *client_licence_buffer = NULL;
        char license[128];

        load_from_file(client_license, &client_licence_buffer);
        sprintf(license, ",\"Version\":\"%s\",", app_version);
        if (!strstr(client_licence_buffer, license))
                exit_on_error(ELICFAIL);

}

void license_for_service(const char *app_version, const char *svc_name, 
                const char *svc_version) {

        if (!app_version || !svc_name || !svc_version)
                exit_on_error(ELICFAIL);

        unsigned char *client_licence_buffer = NULL;
        char license[128];

        load_from_file(client_license, &client_licence_buffer);
        sprintf(license, ",\"Version\":\"%s\",", app_version);
        if (!strstr(client_licence_buffer, license))
                exit_on_error(ELICFAIL);
        sprintf(license, "{\"Name\":\"%s\",\"Version\":\"%s\"}", 
                svc_name, svc_version);
        if (!strstr(client_licence_buffer, license))
                exit_on_error(ELICFAIL);
        

}