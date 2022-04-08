
#include <sys/stat.h>
#include <errno.h>

#include "license.h"

#define ELICFILE 0x0001

#define load_customer_pem() { \
	rsa_client = get_prikey_ex(customer_pem); \
	save_pubkey(customer_pub_pem, rsa_client); \
}

#define load_provider_pub_pem() { \
	rsa_provider = get_pubkey(provider_pub_pem); \
}

#define open_license() { \
        fd_lic = fopen(customer_lic, "w"); \
        if (!fd_lic) \
                on_error(-ELICFILE); \
}

struct app_license *lic = NULL;
RSA *rsa_client = NULL;
RSA *rsa_provider = NULL;
FILE *fd_lic = NULL;
char *session_key = NULL;

void init(int argc, const char *argv[]) {
        
        lic = malloc(sizeof(struct app_license));

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

        fputs(begin_session_ex, fd_lic);
        base64_write_to_file(enc_session_key, fd_lic);
        fputs(end_session_ex, fd_lic);

        free(enc_session_key);
}

void put_customer() {
        char *client_key = NULL;

        int len = load_from_file(customer_pub_pem, &client_key);
	if (len) {
		fputs(client_key, fd_lic);
		free(client_key);
	} else {
		app_exit(ELICFILE);
	}
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

        fputs(begin_license_ex, fd_lic);
        base64_write_to_file(b64_license, fd_lic);
        fputs(end_license_ex, fd_lic);

        free(b64_license);
}

void usage() {

        printf("usage:\nlicense_customer.exe <customer> <issuer> " \
                "<application_version> <service_name:service_version " \
                "[service_name_2:service_version2 ... ]>\n");

        app_exit(0);

}

int main(int argc, const char **argv)
{

        printf("(0/7) initialising...\n");
	crypto_init(app_exit);

        if (argc == 1) {
		printf("generating customer's keys, unless they exist.\n");
		load_customer_pem();
		usage();
        } else if (argc == 2 && !strcmp("verify", argv[1])) {
		printf("verifying the license...\n");
		verify_license();
		app_exit(0);
	} else if (argc < 4) {
		usage();
	}

#ifdef DEBUG
        printf("testing the customer's staff...\n");
#endif
	
        printf("(1/7) loading client...\n");
	load_customer_pem();

        printf("(2/7) loading provider...\n");
	load_provider_pub_pem();

        printf("(3/7) opening license...\n");
	open_license();

        printf("(4/7) saving session...\n");
	put_session();

        printf("(5/7) saving client...\n");
	put_customer();

        printf("(6/7) initialising license...\n");
	init(argc, argv);

        printf("(7/7) saving license...\n");
	put_license();

	printf("done.\n");
	app_exit(0);
}

