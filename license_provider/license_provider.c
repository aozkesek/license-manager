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

#define load_provider_pem() { \
        rsa_provider = get_prikey_ex(provider_pem); \
        save_pubkey(provider_pub_pem, rsa_provider); \
}
 
#define load_customer() { \
        load_from_file(customer_lic, &message_buffer); \
}

struct application *lic = NULL;
RSA *rsa_provider = NULL;
RSA *rsa_client = NULL;

char *message_buffer = NULL;
char *session_key = NULL;
char *license_buffer = NULL;
char *license_buffer_ex = NULL;
char *license_sha_a = NULL;
char *license_sha_b = NULL;

char license_day[10];
#define MAX_DEMO_DAYS 90

/**
 * cleanups then exists
 * @exit_code exit code 
 */
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

/**
 * extracts the sub-value between begin-tag and end-tag;
 *
 * @src source text buffer
 * @tbegin begin tag/keyword
 * @tend end tag/keyword
 */
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

void parse_session() {
        char *base64_buffer = NULL;
        int len;

        base64_buffer = ext_subval_ex(message_buffer, begin_session, end_session);

        len = pri_decrypt(base64_buffer, &session_key, rsa_provider);

        free(base64_buffer);

}

void parse_customer() {
        char *temp_customer_pub = NULL;
	char *temp_pem = "temp-customer-pub.pem";
	
        temp_customer_pub = ext_subval(message_buffer, begin_customer_pub, end_customer_pub);
	
	FILE *fd = fopen(temp_pem, "w");
	if (!fd)
		on_error(-ELICOFL);
	
	fputs(begin_customer_pub, fd);
	fputs(temp_customer_pub, fd);
	fputs(end_customer_pub_ex, fd);
	fclose(fd);
        rsa_client = load_pubkey(temp_pem);
#ifndef DEBUG	
	remove(temp_pem);
#endif
        free(temp_customer_pub);
	
}

void parse_license() {
        char *b64_buffer = NULL;
        char *enc_buffer = NULL;

        b64_buffer = ext_subval_ex(message_buffer, begin_license, end_license);

        int len = base64_decode(b64_buffer, strlen(b64_buffer), &enc_buffer);
        len = decrypt(enc_buffer, len, &license_buffer, session_key);
        license_buffer[len] = 0;
        free(enc_buffer);
        free(b64_buffer);

        char lbuffer[4096];

        if (atoi(license_day) <= MAX_DEMO_DAYS)
                sprintf(lbuffer, "{\"Type\":\"DEMO\",\"ValidFor\":%s,%s",
                        license_day, &license_buffer[1]);
        else
                sprintf(lbuffer, "{\"Type\":\"LIFETIME\",%s",
                        &license_buffer[1]);

        len = strlen(lbuffer);

        reallocate(&license_buffer_ex, len + 1);
        strcpy(license_buffer_ex, lbuffer);
#ifdef DEBUG
	printf("%s\n", lbuffer);
#endif

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

        FILE *fd = fopen(customer_license, "w");

        if (!fd)
                on_error(-ELICOFL);

        fputs(license_buffer_ex, fd);
        fputs("\n", fd);
        fputs(begin_sha_a, fd);
        fputs("\n", fd);
        base64_write_to_file(license_sha_a, fd);
        fputs(end_sha_a, fd);
        fputs("\n", fd);
        fputs(begin_sha_b, fd);
        fputs("\n", fd);
        base64_write_to_file(license_sha_b, fd);
        fputs(end_sha_b, fd);
        fputs("\n", fd);

        fclose(fd);
}

void usage() 
{
        printf("usage:\nlicense_provider [demo | day_count]\n");
        app_exit(0);
}

int main(int argc, char **argv)
{

        crypto_init(app_exit);

        if (argc == 2) {
		int valid_for = MAX_DEMO_DAYS;
                if (strcmp("demo", argv[1])) {
			valid_for = atoi(argv[1]);
			if (valid_for <= 0)
				usage();
		}
                snprintf(license_day, 10, "%d", valid_for);
        } else {
                printf("generating provider's keys, unless they exist.\n");
		load_provider_pem();
		usage();
        } 
	
        printf("loading provider...\n");
        load_provider_pem();

        printf("loading customer...\n");
        load_customer();

        printf("parsing session...\n");
        parse_session();
	
	printf("parsing customer...\n");
	parse_customer();

        printf("parsing license...\n");
        parse_license();

        printf("hashing license...\n");
        hash_license();

        save_license();
        printf("customer's license is saved into the file.\n");

#ifndef DEBUG
        remove(customer_lic);
#endif

        app_exit(0);
}
