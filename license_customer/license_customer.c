
#include <sys/stat.h>
#include <errno.h>

#include <license.h>

#define ELICFILE 0x0001

const char *prov_pri_pem = "provider.pem";
const char *prov_pub_pem = "public_provider.pem";
const char *cli_pri_pem = "customer.pem";
const char *cli_pub_pem = "public_customer.pem";

const char *client_lic = "client.lic";

PLICENSE_STRUCT license = NULL;
RSA *rsa_client = NULL;
RSA *rsa_provider = NULL;
FILE *fd_license = NULL;
unsigned char *session_key = NULL;

void client_private_key_load() {
        rsa_client = rsa_privatekey_load_from_file(cli_pri_pem);
        publickey_write_to_file(cli_pub_pem, rsa_client);
}

void provider_public_key_load() {
        rsa_provider = rsa_publickey_read_from_file(prov_pub_pem);
}

void license_init(int argc, const char **argv) {
        
        license = malloc(sizeof(LICENSE_STRUCT));

        strcpy(license->acquirer, argv[1]);
        strcpy(license->issuer, argv[2]);
        strcpy(license->version, argv[3]);
        license->service_size = argc - 4;
        license->services = malloc(sizeof(SERVICE_STRUCT) * argc - 4);

        memset(license->services, 0, sizeof(SERVICE_STRUCT) * argc - 4);

        char *p = NULL;
        for (int i = 4; i < argc; i++) {
                p = strstr(argv[i], ":");
                if (p) {  
                        strncpy(license->services[i - 4].name, argv[i], 
                                p - argv[i]);
                        strcpy(license->services[i - 4].version, p + 1);
                } else {
                        strcpy(license->services[i - 4].name, argv[i]);
                        strcpy(license->services[i - 4].version, "DEMO");
                }
        }

}

void license_free() {
        if (!license) return;
        if (license->services) free(license->services);
        free(license);        
}

void program_exit(int exit_code) {

        if (rsa_provider) RSA_free(rsa_provider);
        if (rsa_client) RSA_free(rsa_client);

        if (session_key) free(session_key);
        if (fd_license) fclose(fd_license);
        
        license_free();
        crypto_final();

        printf("program terminated with code (%d).\n", exit_code);

        exit(exit_code);
}
 
int license_size() {
        int len = 0;

        char *license_json = 
                "{'Version':'','LicensedTo':'','IssuedBy':'','Services':[]}";
        char *license_services_json = "{'Name':'','Version':''},";

        len += strlen(license->issuer);
        len += strlen(license->acquirer);
        len += strlen(license->version);

        len += 2; //plicense->Service_Count

        int i = 0;
        for(; i < license->service_size; i++) {
                len += strlen(license->services[i].name);
                len += strlen(license->services[i].version);
        }

        return len + strlen(license_json) + 
                license->service_size * strlen(license_services_json);
}
 
void license_to_json_string(char **slicense) {

        int slen = license_size();
        reallocate((unsigned char **)slicense, slen);
        
        sprintf(*slicense,
                "{\"Version\":\"%s\",\"LicensedTo\":\"%s\",\"IssuedBy\":\"%s\",\"Services\":["
                , license->version
                , license->acquirer
                , license->issuer
                );

        int i, pos = strlen(*slicense);

        for (i = 0; i < license->service_size; i++) {
                sprintf(*slicense + pos
                        , "{\"Name\":\"%s\",\"Version\":\"%s\"}"
                        , license->services[i].name
                        , license->services[i].version);
                pos = strlen(*slicense) ;
                if (i < license->service_size - 1)
                        sprintf(*slicense + pos++, ",");
        }

        pos = strlen(*slicense);
        sprintf(*slicense + pos, "]}");

}

void session_key_put_into_license() {

        unsigned char *enc_session_key = NULL;

        generate_random_key(16, &session_key);
        public_encrypt_base64_buffer(strlen((char *)session_key), 
                                session_key, &enc_session_key, rsa_provider);

        fputs("---BEGIN SESSION KEY---\n", fd_license);
        base64_write_to_file(enc_session_key, fd_license);
        fputs("---END SESSION KEY---\n", fd_license);

        free(enc_session_key);
}

void client_key_put_into_license() {
        unsigned char *client_key = NULL;
        unsigned char *client_enc_key = NULL;

        int len = load_from_file(cli_pri_pem, &client_key);
        len = encrypt(client_key, len, &client_enc_key, session_key);
        base64_encode(client_enc_key, len, &client_key);
        free(client_enc_key);

        fputs("---BEGIN RSA PRIVATE KEY---\n", fd_license);
        base64_write_to_file(client_key, fd_license);        
        fputs("---END RSA PRIVATE KEY---\n", fd_license);
        
        free(client_key);
}

void client_license_info_add() {

        unsigned char *clr_license = NULL;
        license_to_json_string((char **)&clr_license);

        unsigned char *enc_license = NULL;
        int elen = encrypt(clr_license, strlen((char *)clr_license), 
                                &enc_license, session_key);
        
        free(clr_license);

        unsigned char *b64_license = NULL;
        base64_encode(enc_license, elen, &b64_license);

        free(enc_license);

        fputs("---BEGIN LICENSE---\n", fd_license);
        base64_write_to_file(b64_license, fd_license);
        fputs("---END LICENSE---\n", fd_license);

        free(b64_license);
}

void program_usage() {

        printf("usage:\nlicense_public.exe <acquirer> <issuer> " \
                "<appication_version> <service_name:service_version " \
                "[service_name_2:service_version2 ... ]>\n");

        program_exit(-11);

}

int main(int argc, const char **argv)
{
	crypto_init();

	if (argc < 4)
		program_usage();

	client_private_key_load();
        printf("customer key is loaded.\n");

	provider_public_key_load();
        printf("provider's public key is loaded.\n");

	fd_license = fopen(client_lic, "w");
	if (!fd_license)
		exit_on_error(-ELICFILE);
        printf("customer license file is opened.\n");

	session_key_put_into_license();
        printf("encrypted session key is saved into the license file.\n");

	client_key_put_into_license();
        printf("customer key is saved into the license file.\n");

	license_init(argc, argv);
        printf("license is initialized.\n");

	client_license_info_add();
        printf("license is saved into the license file.\n");

	program_exit(0);
}
