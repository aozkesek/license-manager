
#include <sys/stat.h>
#include <errno.h>

#include "license.h"

#define ELICFILE 0x0001

#define load_client_prikey() { \
	rsa_client = get_prikey_ex(cli_pri_pem); \
	save_pubkey(cli_pub_pem, rsa_client); \
}

#define load_provider_pubkey() { \
	rsa_provider = get_pubkey(prov_pub_pem); \
}

struct application *lic = NULL;
RSA *rsa_client = NULL;
RSA *rsa_provider = NULL;
FILE *fd_lic = NULL;
char *session_key = NULL;

void init(int argc, const char *argv[]) {
        
        lic = malloc(sizeof(struct application));

        strcpy(lic->acquirer, argv[1]);
        strcpy(lic->issuer, argv[2]);
        strcpy(lic->version, argv[3]);
        lic->svcs_size = argc - 4;
        lic->svcs = malloc(sizeof(struct service) * argc - 4);

        memset(lic->svcs, 0, sizeof(struct service) * argc - 4);

        char *p = NULL;
        for (int i = 4; i < argc; i++) {
                p = strstr(argv[i], ":");
                if (p) {  
                        strncpy(lic->svcs[i - 4].name, argv[i], p - argv[i]);
                        strcpy(lic->svcs[i - 4].version, p + 1);
                } else {
                        strcpy(lic->svcs[i - 4].name, argv[i]);
                        strcpy(lic->svcs[i - 4].version, "DEMO");
                }
        }

}

void final() {
	if (!lic)
		return;
	if (lic->svcs)
		free(lic->svcs);
	free(lic);
}

void app_exit(int exit_code) {

        if (rsa_provider) RSA_free(rsa_provider);
        if (rsa_client) RSA_free(rsa_client);

        if (session_key) free(session_key);
        if (fd_lic) fclose(fd_lic);
        
        final();
        crypto_final();

        printf("program terminated with code (%d).\n", exit_code);

        exit(exit_code);
}
 
int size() {
        int len = 0;

        char *license_json = 
                "{'Version':'','LicensedTo':'','IssuedBy':'','Services':[]}";
        char *license_services_json = "{'Name':'','Version':''},";

        len += strlen(lic->issuer);
        len += strlen(lic->acquirer);
        len += strlen(lic->version);

        len += 2; //plic->Service_Count

        int i = 0;
        for(; i < lic->svcs_size; i++) {
                len += strlen(lic->svcs[i].name);
                len += strlen(lic->svcs[i].version);
        }

        return len + strlen(license_json) + 
                lic->svcs_size * strlen(license_services_json);
}
 
void to_json_string(char **slicense) {

        int slen = size();
        reallocate(slicense, slen);
        
        sprintf(*slicense,
                "{\"Version\":\"%s\",\"LicensedTo\":\"%s\",\"IssuedBy\":\"%s\",\"Services\":["
                , lic->version
                , lic->acquirer
                , lic->issuer
                );

        int i, pos = strlen(*slicense);

        for (i = 0; i < lic->svcs_size; i++) {
                sprintf(*slicense + pos
                        , "{\"Name\":\"%s\",\"Version\":\"%s\"}"
                        , lic->svcs[i].name
                        , lic->svcs[i].version);
                pos = strlen(*slicense) ;
                if (i < lic->svcs_size - 1)
                        sprintf(*slicense + pos++, ",");
        }

        pos = strlen(*slicense);
        sprintf(*slicense + pos, "]}");

}

void put_session() {

        char *enc_session_key = NULL;

        gen_session_key(16, &session_key);
        pub_encrypt(strlen(session_key), session_key, &enc_session_key, rsa_provider);

        fputs("---BEGIN SESSION KEY---\n", fd_lic);
        base64_write_to_file(enc_session_key, fd_lic);
        fputs("---END SESSION KEY---\n", fd_lic);

        free(enc_session_key);
}

void put_client() {
        char *client_key = NULL;
        char *client_enc_key = NULL;

        int len = load_from_file(cli_pri_pem, &client_key);
        len = encrypt(client_key, len, &client_enc_key, session_key);
        base64_encode(client_enc_key, len, &client_key);
        free(client_enc_key);

        fputs("---BEGIN RSA PRIVATE KEY---\n", fd_lic);
        base64_write_to_file(client_key, fd_lic);
        fputs("---END RSA PRIVATE KEY---\n", fd_lic);
        
        free(client_key);
}

void put_license() {

        char *clr_license = NULL;
        to_json_string(&clr_license);

        char *enc_license = NULL;
        int elen = encrypt(clr_license, strlen(clr_license), &enc_license, session_key);
        
        free(clr_license);

        char *b64_license = NULL;
        base64_encode(enc_license, elen, &b64_license);

        free(enc_license);

        fputs("---BEGIN LICENSE---\n", fd_lic);
        base64_write_to_file(b64_license, fd_lic);
        fputs("---END LICENSE---\n", fd_lic);

        free(b64_license);
}

void usage() {

        printf("usage:\nlicense_public.exe <client> <issuer> " \
                "<application_version> <service_name:service_version " \
                "[service_name_2:service_version2 ... ]>\n");

        app_exit(-11);

}

void test_self() 
{       
        const char *args[] = { "tester", "testee", "1.0", "testserv:1.0" };
        const char *tmpcuspri = "tmp-customer.pem";
        const char *tmpcuspub = "tmp-customer-pub.pem";
        const char *tmppropub = "tmp-provider-pub.pem";

        printf("testing the customer's staff...\n");
        init(4, args);



}

void generate_keys()
{
        const char *tmpcuspri = "tmp-customer.pem";
        const char *tmpcuspub = "tmp-customer-pub.pem";
        rsa_client = get_prikey_ex(tmpcuspri);
        save_pubkey(tmpcuspub, rsa_client);
        printf("test keys are generated.\n");
}

int main(int argc, const char **argv)
{

        printf("(0/7) initialising...\n");
	crypto_init(app_exit);

        if (argc == 2) {
                if (!strcmp(argv[1], "test"))
                        test_self();
                else if (!strcmp(argv[1], "genkey"))
                        generate_keys();
                app_exit(0);
        } else if (argc < 4) {
                printf("generating keys, unless they exist.\n");
                load_client_prikey();
                usage();
        }

        printf("(1/7) loading client...\n");
	load_client_prikey();

        printf("(2/7) loading provider...\n");
	load_provider_pubkey();

        printf("(3/7) opening license...\n");
	fd_lic = fopen(client_lic, "w");
	if (!fd_lic)
		on_error(-ELICFILE);

        printf("(4/7) saving session...\n");
	put_session();

        printf("(5/7) saving client...\n");
	put_client();

        printf("(6/7) initialising license...\n");
	init(argc, argv);

        printf("(7/7) saving license...\n");
	put_license();

	printf("done.\n");
	app_exit(0);
}

