
#include <license.h>

#define ERDFILE 0x0001

//global variables
const char *prov_pri_pem = "provider.pem";
const char *prov_pub_pem = "public_provider.pem";
const char *client_lic = "client.lic";
char *cli_pri_pem = NULL;
char *cli_pub_pem = NULL;

const char *begin_session = "---BEGIN SESSION KEY---";
const char *end_session = "---END SESSION KEY---";
const char *begin_public = "-----BEGIN RSA PUBLIC KEY-----";
const char *end_public = "-----END RSA PUBLIC KEY-----";
const char *begin_license = "---BEGIN LICENSE---";
const char *end_license = "---END LICENSE---";
const char *begin_license_sha1a = "---BEGIN SHA1 A---";
const char *end_license_sha1a = "---END SHA1 A---";
const char *begin_license_sha1b = "---BEGIN SHA1 B---";
const char *end_license_sha1b = "---END SHA1 B---";

PLICENSE_SHA_STRUCT license = NULL;
RSA *rsa_provider = NULL;
RSA *rsa_client = NULL;

unsigned char *session_key = NULL;
unsigned char *license_buffer = NULL;
unsigned char *license_buffer_ex = NULL;
unsigned char *message_buffer = NULL;
unsigned char *license_sha1a = NULL;
unsigned char *license_sha1b = NULL;

char license_day[10];

void program_usage() {
	printf("usage:\nlicense_manager [test | day_count]\n");
	exit(1);
}

void program_exit(int exit_code) {

	if (rsa_provider) RSA_free(rsa_provider);
	if (rsa_client) RSA_free(rsa_client);

	if (session_key) free(session_key);
	if (message_buffer) free(message_buffer);
	if (license_sha1a) free(license_sha1a);
	if (license_sha1b) free(license_sha1b);
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

int load_from_file(const char *fname, char **buffer) {
 
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
        fread(buffer, flen, 1, file); 
        fclose(file);
 
        buffer[flen] = 0;
 
        return flen;
}
 
void load_message_from_client() {
	message_buffer = load_from_file(client_lic);
}

void session_key_parse() {
	char *b64_buffer = NULL;
	unsigned char *enc_buffer = NULL;
	int len;

	b64_buffer = sub_value_extract_trim((const char *)message_buffer, 
                                        begin_session, end_session);
	if (b64_buffer) {
		len = base64_decode((unsigned char *)b64_buffer, &enc_buffer);
		if (len) {
			session_key = malloc(len);
			len = private_decrypt_buffer(len, enc_buffer, 
                                                session_key, rsa_provider);
			if (len)
				session_key[len] = 0;
			free(enc_buffer);
		}
		free(b64_buffer);
	}

	if (!session_key)
		program_exit(3);

}

void client_public_key_parse() {
	char *b64_buffer = NULL;
	char *pem_temp_client = "pub_temp_client.pem";
	char fname[PATH_MAX];

	b64_buffer = sub_value_extract((const char *)message_buffer, begin_public, end_public);
	if (b64_buffer) {
		FILE *fd = fopen(fullname(pem_temp_client, fname), "w");
		if (fd) {
			fputs(begin_public, fd);
			fputs(b64_buffer, fd);
			fputs(end_public, fd);
			fputs("\n", fd);
			fclose(fd);
			rsa_client = rsa_publickey_load_from_file(fullname(pem_temp_client, fname));
		}
		free(b64_buffer);
	}

	if (!rsa_client)
		program_exit(4);

}

void license_message_parse() {
	char *b64_buffer = NULL;
	unsigned char *enc_buffer = NULL;

	b64_buffer = sub_value_extract_trim((const char *)message_buffer, begin_license, end_license);
	if (!b64_buffer)
		program_exit(5);

	int len = base64_decode((unsigned char *)b64_buffer, &enc_buffer);
	if (len) {
		len = decrypt(enc_buffer, len, &license_buffer, session_key);
		if (len)
			license_buffer[len] = 0;
		free(enc_buffer);
	}
	free(b64_buffer);

	if (!license_buffer)
		program_exit(5);

	char lbuffer[4096];

	if (strlen(license_day) > 0)
		sprintf(lbuffer, "{\"Type\":\"DEMO\",\"ValidFor\":%s,%s", license_day, &license_buffer[1]);
	else
		sprintf(lbuffer, "{\"Type\":\"LIFETIME\",%s", &license_buffer[1]);

	len = strlen(lbuffer);

	license_buffer_ex = malloc(len + 1);
	memset(license_buffer_ex, 0, len + 1);
	strcpy((char *)license_buffer_ex, lbuffer);

}

void sha1_license_buffer() {
	unsigned char *sha1_buffer = NULL;
	unsigned char *b64_provider_enc_buffer = NULL;
	unsigned char half_buffer[512];

	if (!sha1(license_buffer_ex, strlen((char *)license_buffer_ex), &sha1_buffer))
		program_exit(7);

	int elen = private_encrypt_b64(strlen((char *)sha1_buffer), sha1_buffer, &b64_provider_enc_buffer, rsa_provider);
	if (elen < 1) {
		print_last_error();
		free(sha1_buffer);
		program_exit(7);
	}

	free(sha1_buffer);

	int slen = strlen((char *)b64_provider_enc_buffer);
	int blen = slen / 2;

	memset(half_buffer, 0, 512);
	memcpy(half_buffer, b64_provider_enc_buffer, blen);

	elen = public_encrypt_b64(strlen((char *)half_buffer), half_buffer, &license_sha1a, rsa_client);
	if (elen < 1) {
		print_last_error();
		free(b64_provider_enc_buffer);
		program_exit(7);
	}

	memset(half_buffer, 0, 512);
	memcpy(half_buffer, b64_provider_enc_buffer + blen, slen - blen);

	elen = public_encrypt_b64(strlen((char *)half_buffer), half_buffer, &license_sha1b, rsa_client);

	free(b64_provider_enc_buffer);

	if (elen < 1) {
		print_last_error();
		program_exit(7);
	}

}

void client_license_write() {
	char fname[PATH_MAX];

	FILE *fd = fopen(fullname("client.license", fname), "w");

	if (fd) {
		fputs((const char *)license_buffer_ex, fd);
		fputs("\n", fd);
		fputs(begin_license_sha1a, fd);
		fputs("\n", fd);
		base64_write_to_file(license_sha1a, fd);
		fputs(end_license_sha1a, fd);
		fputs("\n", fd);
		fputs(begin_license_sha1b, fd);
		fputs("\n", fd);
		base64_write_to_file(license_sha1b, fd);
		fputs(end_license_sha1b, fd);
		fputs("\n", fd);

		fclose(fd);
	}

}

void newline_trim(char *p) {
	int i = strlen(p);
	while ('\n' == p[i - 1] || '\r' == p[i - 1])
		p[--i] = 0;
}

void client_license_test() {

	char fname[PATH_MAX];

	FILE *fd = fopen(fullname("client.license", fname), "r");
	if (fd) {

		unsigned char license[4096];
		unsigned char line[96];
		unsigned char sha1a[1024];
		unsigned char sha1b[1024];

		memset(license, 0, 4096);
		memset(sha1a, 0, 1024);
		memset(sha1b, 0, 1024);

		if (fgets((char *)license, 4096, fd)) {

			newline_trim((char *)license);

			short isSha1a = 0;
			short isSha1b = 0;
			short bsha1alen = strlen(begin_license_sha1a);
			short bsha1blen = strlen(begin_license_sha1b);
			short esha1alen = strlen(end_license_sha1a);
			short esha1blen = strlen(end_license_sha1b);

			while (!feof(fd) && fgets((char *)line, 96, fd)) {

				if (!memcmp(line, begin_license_sha1a, bsha1alen)) {
					isSha1a = 1;
					isSha1b = 0;
					continue;
				}
				else if (!memcmp(line, begin_license_sha1b, bsha1blen)) {
					isSha1a = 0;
					isSha1b = 1;
					continue;
				}
				else if (!memcmp(line, end_license_sha1a, esha1alen)) {
					isSha1a = 0;
					isSha1b = 0;
					continue;
				}
				else if (!memcmp(line, end_license_sha1b, esha1blen)) {
					isSha1a = 0;
					isSha1b = 0;
					continue;
				}

				newline_trim((char *)line);

				if (isSha1a)
					strcat((char *)sha1a, (const char *)line);
				else if (isSha1b)
					strcat((char *)sha1b, (const char *)line);

			}

		}

		fclose(fd);

		int rc = LicenseSha1(path_name, license, sha1a, sha1b);
		printf("TEST(%d) => %s\n", rc, !rc ? "OK":"FAIL");

	}




}

int main(int argc, char **argv)
{

        crypto_init();

        if (argc < 2) {
                program_usage();
                program_exit(0);
        }

        memset(path_name, 0, PATH_MAX);
        strcpy(path_name, argv[1]);

        if (argc == 3) {
                if (!memcmp("test", argv[2], 4)) {
                	        client_license_test();
                	        program_exit(0);
                }

                int test_day = atoi(argv[2]);
                if ( test_day <= 0 || test_day > 90 ) {
                        program_usage();
                        program_exit(0);
                }
                snprintf(license_day, 10, "%d", test_day);
        }

        provider_private_key_load();

        load_message_from_client();

        session_key_parse();

        client_public_key_parse();

        license_message_parse();

        sha1_license_buffer();

        client_license_write();

        client_license_test();

        program_exit(0);
}
