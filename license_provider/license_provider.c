#include "license.h"

#define EEXTRAC 0x0001
#define ELICOFL 0x0002
#define EPEMOFL 0x0003
#define ELICTST 0x0101

#define trim_newline(p) { \
	int i = strlen(p); \
	while ('\n' == p[i - 1] || '\r' == p[i - 1]) \
		p[--i] = 0; \
}

#define load_provider() { \
        rsa_provider = get_prikey_ex(prov_pri_pem); \
        save_pubkey(prov_pub_pem, rsa_provider); \
}
 
#define load_client() { \
        load_from_file(client_lic, &message_buffer); \
}

struct application *lic = NULL;
RSA *rsa_provider = NULL;
RSA *rsa_client = NULL;

char *session_key = NULL;
char *license_buffer = NULL;
char *license_buffer_ex = NULL;
char *message_buffer = NULL;
char *license_sha_a = NULL;
char *license_sha_b = NULL;

char license_day[10];

void app_exit(int exit_code) 
{

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

/**
 * extracts the sub-value between begin-tag and end-tag and trim new line(s) in it;
 *
 * @src source text buffer
 * @tbegin begin tag/keyword
 * @tend end tag/keyword
 */
char *extract_subval_ex(const char *src, const char *tbegin, const char *tend)
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

/**
 * extracts the sub-value between begin-tag and end-tag;
 *
 * @src source text buffer
 * @tbegin begin tag/keyword
 * @tend end tag/keyword
 */
char *extract_subval(const char *src, const char *tbegin, const char *tend)
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

void parse_session() {
        char *base64_buffer = NULL;
        int len;

        base64_buffer = extract_subval_ex(message_buffer, begin_session, end_session);

        len = pri_decrypt(base64_buffer, &session_key, rsa_provider);

        free(base64_buffer);

}

void parse_keys() {
        char *base64_buffer = NULL;
        char *pem_temp_client = "temp_customer.pem";

        base64_buffer = extract_subval_ex(message_buffer, begin_key, end_key);

        char *client_enc_key = NULL;
        int len = base64_decode(base64_buffer, strlen(base64_buffer), &client_enc_key);
        char *client_key = NULL;
        len = decrypt(client_enc_key, len, &client_key, session_key);

        FILE *fd = fopen(pem_temp_client, "w");
        if (!fd)
                on_error(-EPEMOFL);
        fputs(client_key, fd);
        fclose(fd);
        rsa_client = get_prikey_ex(pem_temp_client);
        remove(pem_temp_client);
        free(base64_buffer);
	
}

void parse_license() {
        char *b64_buffer = NULL;
        char *enc_buffer = NULL;

        b64_buffer = extract_subval_ex(message_buffer, begin_license, end_license);

        int len = base64_decode(b64_buffer, strlen(b64_buffer), &enc_buffer);
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
        strcpy(license_buffer_ex, lbuffer);

}

void hash_license() {
        char *sha_buffer = NULL;
        char *base64_provider_enc_buffer = NULL;
        char half_buffer[512];

        digest(license_buffer_ex, strlen(license_buffer_ex), &sha_buffer);

        int elen = pri_encrypt(strlen(sha_buffer), sha_buffer, &base64_provider_enc_buffer, rsa_provider);

        free(sha_buffer);

        int slen = strlen(base64_provider_enc_buffer);
        int blen = slen / 2;

        memset(half_buffer, 0, 512);
        memcpy(half_buffer, base64_provider_enc_buffer, blen);

        elen = pub_encrypt(strlen(half_buffer), half_buffer, &license_sha_a, rsa_client);

        memset(half_buffer, 0, 512);
        memcpy(half_buffer, base64_provider_enc_buffer + blen, slen - blen);

        elen = pub_encrypt(strlen(half_buffer), half_buffer, &license_sha_b, rsa_client);

        free(base64_provider_enc_buffer);

}

void save_license() {

        FILE *fd = fopen(client_license, "w");

        if (!fd)
                on_error(-ELICOFL);

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

void load_license(char **license, char **sha_a, char **sha_b) {

        char *client_lic_buffer = NULL;
        load_from_file(client_license, &client_lic_buffer);
        *sha_a = extract_subval_ex(client_lic_buffer, begin_license_sha_a, end_license_sha_a);
        *sha_b = extract_subval_ex(client_lic_buffer, begin_license_sha_b, end_license_sha_b);
        int len = strstr(client_lic_buffer, begin_license_sha_a) - (char *)client_lic_buffer;
        reallocate(license, len + 1);
        memcpy(*license, client_lic_buffer, len);
        trim_newline(*license);
}

void test_license() {

        char *license = NULL;
        char *sha_a = NULL;
        char *sha_b = NULL;
        load_license(&license, &sha_a, &sha_b);
        build_sha(license, sha_a, sha_b);
        printf("OK, licence is tested.\n");

        app_exit(0);

}

void test_library()
{
        printf("testing the library functions...\n");
        base64_selftest();
        crypto_selftest();
        rsa_selftest();
        license_selftest();

        app_exit(0);
}

void usage() 
{
        printf("usage:\nlicense_manager [test | day_count]\n");
        app_exit(1);
}

int main(int argc, char **argv)
{

        crypto_init(app_exit);

        if (argc == 2) {
                if (!strcmp("testlicense", argv[1]))
                	test_license();
                else if (!strcmp("test", argv[1]))
                        test_library();

                int test_day = atoi(argv[1]);
                if ( test_day <= 0 || test_day > 90 )
                        usage();

                snprintf(license_day, 10, "%d", test_day);
        }
        else if (argc > 2) {

                if (memcmp("test", argv[1], 4))
                        usage();
                
                if (argc == 3)
                        license_app(argv[2]);
                else if (argc == 5)
                        license_service(argv[2], argv[3], argv[4]);
                else
                        usage();
                printf("license is valid for application/service.\n");
                app_exit(0);
        }

        printf("loading provider...\n");
        load_provider();

        printf("loading client...\n");
        load_client();

        printf("parsing session...\n");
        parse_session();

        printf("parsing license...\n");
        parse_license();

        printf("hashing license...\n");
        hash_license();

        save_license();
        printf("customer's license is saved into the file.\n");

        //remove(client_lic);

        test_license();

        app_exit(0);
}
