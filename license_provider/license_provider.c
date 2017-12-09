
#include <license.h>

#define EEXTRAC 0x0001
#define ELICOFL 0x0002
#define EPEMOFL 0x0003
#define ELICTST 0x0101

//global variables
extern const char *prov_pri_pem;
extern const char *prov_pub_pem;
extern const char *client_lic;
extern const char *client_license;
extern const char *cli_pri_pem;
extern const char *cli_pub_pem;

extern const char *begin_session;
extern const char *end_session;
extern const char *begin_key;
extern const char *end_key;
extern const char *begin_license;
extern const char *end_license;
extern const char *begin_license_sha_a;
extern const char *end_license_sha_a;
extern const char *begin_license_sha_b;
extern const char *end_license_sha_b;

PLICENSE_SHA_STRUCT license = NULL;
RSA *rsa_provider = NULL;
RSA *rsa_client = NULL;

unsigned char *session_key = NULL;
unsigned char *license_buffer = NULL;
unsigned char *license_buffer_ex = NULL;
unsigned char *message_buffer = NULL;
unsigned char *license_sha_a = NULL;
unsigned char *license_sha_b = NULL;

char license_day[10];

void newline_trim(char *p) {
        int i = strlen(p);
        while ('\n' == p[i - 1] || '\r' == p[i - 1])
                p[--i] = 0;
}

void program_usage() {
        printf("usage:\nlicense_manager [test | day_count]\n");
        program_exit(1);
}

void program_exit(int exit_code) {

        if (rsa_provider) RSA_free(rsa_provider);
        if (rsa_client) RSA_free(rsa_client);

        if (session_key) free(session_key);
        if (message_buffer) free(message_buffer);
        if (license_sha_a) free(license_sha_a);
        if (license_sha_b) free(license_sha_b);
        if (license_buffer) free(license_buffer);
        if (license_buffer_ex) free(license_buffer_ex);

        crypto_final();

        printf("program terminated with code (%d).\n", exit_code);

        exit(exit_code);
}

void provider_private_key_load() {
        rsa_provider = rsa_privatekey_load_from_file(prov_pri_pem);
        publickey_write_to_file(prov_pub_pem, rsa_provider);
}
 
void load_message_from_client() {
        load_from_file(client_lic, &message_buffer);
}

char *sub_value_extract_trim(const char *lic_client, 
                        const char *begin_title, const char *end_title) {

        char *p_begin_title = strstr(lic_client, begin_title);
        if (!p_begin_title)
                exit_on_error(-EEXTRAC);

        char *p_end_title = strstr(lic_client, end_title);
        if (!p_end_title)
                exit_on_error(-EEXTRAC);

        int i = 0,
                j = 0,
                pos = strlen(begin_title),
                len = p_end_title - p_begin_title - pos;
        char *key = malloc(len + 1);
        memset(key, 0, len + 1);
        while (i < len) {
                if (p_begin_title[pos + i] != '\n')
                        key[j++] = p_begin_title[pos + i];
                i++;
        }

        return key;

}

char *sub_value_extract(const char *lic_client, 
                        const char *begin_title, const char *end_title) {
 
        char *p_begin_title = strstr(lic_client, begin_title);
        if (!p_begin_title)
                exit_on_error(-EEXTRAC);

        char *p_end_title = strstr(lic_client, end_title);
        if (!p_end_title)
                exit_on_error(-EEXTRAC);

        int i = 0,
                j = 0,
                pos = strlen(begin_title),
                len = p_end_title - p_begin_title - pos;
        char *key = malloc(len + 1);
        memset(key, 0, len + 1);
        while (i < len)
                key[j++] = p_begin_title[pos + i++];

        return key;

}

void session_key_parse() {
        unsigned char *base64_buffer = NULL;
        int len;

        base64_buffer = sub_value_extract_trim((const char *)message_buffer,
                                        begin_session, end_session);

        len = private_decrypt_base64_buffer(base64_buffer, &session_key,
                                                rsa_provider);

        free(base64_buffer);

}

void client_key_parse() {
        char *base64_buffer = NULL;
        char *pem_temp_client = "temp_customer.pem";

        base64_buffer = sub_value_extract_trim((const char *)message_buffer, 
                                                begin_key, end_key);

        unsigned char *client_enc_key = NULL;
        int len = base64_decode(base64_buffer, &client_enc_key);
        unsigned char *client_key = NULL;
        len = decrypt(client_enc_key, len, &client_key, session_key);

        FILE *fd = fopen(pem_temp_client, "w");
        if (!fd)
                exit_on_error(-EPEMOFL);
        fputs(client_key, fd);
        fclose(fd);
        rsa_client = rsa_privatekey_load_from_file(pem_temp_client);
        remove(pem_temp_client);
        free(base64_buffer);
	
}

void license_message_parse() {
        char *b64_buffer = NULL;
        unsigned char *enc_buffer = NULL;

        b64_buffer = sub_value_extract_trim((const char *)message_buffer,
                                        begin_license, end_license);

        int len = base64_decode((unsigned char *)b64_buffer, &enc_buffer);
        len = decrypt(enc_buffer, len, &license_buffer, session_key);
        license_buffer[len] = 0;
        free(enc_buffer);
        free(b64_buffer);

        char lbuffer[4096];

        if (strlen(license_day) > 0)
                sprintf(lbuffer, "{\"Type\":\"DEMO\",\"ValidFor\":%s,%s",
                        license_day, &license_buffer[1]);
        else
                sprintf(lbuffer, "{\"Type\":\"LIFETIME\",%s",
                        &license_buffer[1]);

        len = strlen(lbuffer);

        reallocate(&license_buffer_ex, len + 1);
        strcpy((char *)license_buffer_ex, lbuffer);

}

void sha_license_buffer() {
        unsigned char *sha_buffer = NULL;
        unsigned char *base64_provider_enc_buffer = NULL;
        unsigned char half_buffer[512];

        sha256(license_buffer_ex, strlen((char *)license_buffer_ex),
                        &sha_buffer);

        int elen = private_encrypt_base64_buffer(
                        strlen((char *)sha_buffer), sha_buffer, 
                        &base64_provider_enc_buffer, rsa_provider);

        free(sha_buffer);

        int slen = strlen((char *)base64_provider_enc_buffer);
        int blen = slen / 2;

        memset(half_buffer, 0, 512);
        memcpy(half_buffer, base64_provider_enc_buffer, blen);

        elen = public_encrypt_base64_buffer(strlen((char *)half_buffer),
                                half_buffer, &license_sha_a, rsa_client);

        memset(half_buffer, 0, 512);
        memcpy(half_buffer, base64_provider_enc_buffer + blen, slen - blen);

        elen = public_encrypt_base64_buffer(strlen((char *)half_buffer),
                                half_buffer, &license_sha_b, rsa_client);

        free(base64_provider_enc_buffer);

}

void client_license_write() {

        FILE *fd = fopen(client_license, "w");

        if (!fd)
                exit_on_error(-ELICOFL);

        fputs((const char *)license_buffer_ex, fd);
        fputs("\n", fd);
        fputs(begin_license_sha_a, fd);
        fputs("\n", fd);
        base64_write_to_file(license_sha_a, fd);
        fputs(end_license_sha_a, fd);
        fputs("\n", fd);
        fputs(begin_license_sha_b, fd);
        fputs("\n", fd);
        base64_write_to_file(license_sha_b, fd);
        fputs(end_license_sha_b, fd);
        fputs("\n", fd);

        fclose(fd);
}

void client_licence_load(char **license, char **sha_a, char **sha_b) {

        unsigned char *client_lic_buffer = NULL;
        load_from_file(client_license, &client_lic_buffer);
        *sha_a = sub_value_extract_trim(client_lic_buffer, begin_license_sha_a,
                                end_license_sha_a);
        *sha_b = sub_value_extract_trim(client_lic_buffer, begin_license_sha_b,
                                end_license_sha_b);
        int len = strstr(client_lic_buffer, begin_license_sha_a)  
                        - (char *)client_lic_buffer;
        reallocate((unsigned char **)license, len + 1);
        memcpy(*license, client_lic_buffer, len);
        newline_trim(*license);
}

void client_license_test() {

        char *license = NULL;
        char *sha_a = NULL;
        char *sha_b = NULL;
        client_licence_load(&license, &sha_a, &sha_b);
        license_sha(license, sha_a, sha_b);
        printf("OK, licence is tested.\n");

        program_exit(0);

}

int main(int argc, char **argv)
{

        crypto_init();

        if (argc == 2) {
                if (!memcmp("test", argv[1], 4))
                	client_license_test();

                int test_day = atoi(argv[1]);
                if ( test_day <= 0 || test_day > 90 )
                        program_usage();

                snprintf(license_day, 10, "%d", test_day);
        }
        else if (argc > 2) {

                if (memcmp("test", argv[1], 4))
                        program_usage();
                
                if (argc == 3)
                        license_for_app(argv[2]);
                else if (argc == 5)
                        license_for_service(argv[2], argv[3], argv[4]);
                else
                        program_usage();
                printf("license is valid for application/service.\n");
                program_exit(0);
        }

        provider_private_key_load();
        printf("provider's key is loaded.\n");

        load_message_from_client();
        printf("customer's license is loaded.\n");

        session_key_parse();
        printf("sessionkey is parsed.\n");

        client_key_parse();
        printf("customer's key is parsed.\n");

        license_message_parse();
        printf("customer's license is parsed.\n");

        sha_license_buffer();
        printf("customer's license is generated.\n");

        client_license_write();
        printf("customer's license is saved into the file.\n");

        remove(client_lic);

        client_license_test();

        program_exit(0);
}
