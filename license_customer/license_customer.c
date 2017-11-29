#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <memory.h>
#include <errno.h>

#include <license.h>

const char *pri_client = "pri_client.pem";
const char *pub_client = "pub_client.pem";
const char *pub_provider = "pub_provider.pem";
const char *client_lic = "client.lic";

PLICENSE_STRUCT license = NULL;
RSA *rsa_client = NULL;
RSA *rsa_provider = NULL;
FILE *fd_license = NULL;
byte *session_key = NULL;
char path_name[_MAX_PATH];

char *fullname(const char *name, char *fullname) {

	sprintf(fullname, "%s/%s", path_name, name);
	return  fullname;

}

void program_exit(int exit_code) {

	if (!rsa_provider) RSA_free(rsa_provider);
	if (!rsa_client) RSA_free(rsa_client);

	if (session_key) free(session_key);
	if (fd_license) fclose(fd_license);
	if (license) free(license);

	lib_finalize();

	printf("program terminated with code (%d).\n", exit_code);

	exit(exit_code);
}

void client_private_key_load() {
	char fname[_MAX_PATH];

	rsa_client = rsa_privatekey_load_from_file(fullname(pri_client, fname));
	if (!rsa_client) {
		print_last_error();
		program_exit(1);
	}
	publickey_write_to_file(fullname(pub_client, fname), rsa_client);
}

void provider_public_key_load() {
	char fname[_MAX_PATH];

	rsa_provider = rsa_publickey_read_from_file(fullname(pub_provider, fname));
	if (!rsa_provider) {
		print_last_error();
		program_exit(2);
	}

}

void session_key_create() {

	generate_random_key(&session_key, 16);
	if (!session_key)
		program_exit(40);

	int size = RSA_size(rsa_provider);
	byte *enc_session_key = malloc(size);

	memset(enc_session_key, 0, size);

	int elen = public_encrypt_buffer(strlen((char *)session_key), session_key, enc_session_key, rsa_provider);
	if (!elen) {
		free(enc_session_key);
		program_exit(41);
	}

	byte *b64_session_key = NULL;
	base64_encode(enc_session_key, elen, &b64_session_key);
	if (!b64_session_key) {
		free(enc_session_key);
		program_exit(42);
	}

	free(enc_session_key);

	fputs("---BEGIN SESSION KEY---\n", fd_license);
	base64_write_to_file(b64_session_key, fd_license);
	fputs("---END SESSION KEY---\n", fd_license);

	free(b64_session_key);

}

void client_public_key_add() {
	char fname[_MAX_PATH];

	byte *public_client = load_from_file(fullname(pub_client, fname));
	if (!public_client)
		program_exit(5);

	fputs((const char *)public_client, fd_license);
	free(public_client);

}

void client_license_info_add() {

	byte *clr_license = NULL;
	license_to_json_string(license, (char **)&clr_license);
	if (!clr_license)
		program_exit(61);

	byte *enc_license = NULL;
	int elen = encrypt(clr_license, strlen((char *)clr_license), &enc_license, session_key);
	if (!elen || !enc_license) {
		free(clr_license);
		program_exit(62);
	}

	free(clr_license);

	byte *b64_license = NULL;
	base64_encode(enc_license, elen, &b64_license);
	if (!b64_license) {
		free(enc_license);
		program_exit(63);
	}

	free(enc_license);

	fputs("---BEGIN LICENSE---\n", fd_license);
	base64_write_to_file(b64_license, fd_license);
	fputs("---END LICENSE---\n", fd_license);

	free(b64_license);
}

void program_usage() {

	printf("usage:\nlicense_public.exe <full_path_name_of_the_pem_files> " \
                "<version_of_the_app> <service_name:service_version [service_name_2:service_version2 ... ]>\n");

	program_exit(-1);

}

int main(int argc, const char **argv)
{
	char fname[_MAX_PATH];

	lib_initialize();

	if (argc < 3)
		program_usage();

	memset(path_name, 0, _MAX_PATH);
	strcpy(path_name, argv[1]);

	client_private_key_load();

	provider_public_key_load();

	fd_license = fopen(fullname(client_lic, fname), "w");
	if (!fd_license)
		program_exit(3);

	session_key_create();

	client_public_key_add();

	license = license_init(argc, argv);
	if (!license)
		program_exit(6);

	client_license_info_add();

	program_exit(0);
}
