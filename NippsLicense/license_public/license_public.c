#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <memory.h>
#include <errno.h>

#include <license.h>

const byte *pri_client = "pri_client.pem";
const byte *pub_client = "pub_client.pem";
const byte *pub_netas = "pub_netas.pem";
const byte *client_lic = "client.lic";

PLICENSE_STRUCT *license = NULL;
RSA *rsa_client = NULL;
RSA *rsa_netas = NULL;
FILE *fd_license = NULL;
byte *session_key = NULL;
byte path_name[_MAX_PATH];

byte *fullname(byte *name, byte *fullname) {

	sprintf(fullname, "%s\\%s", path_name, name);
	return  fullname;

}

void exit_program(int exit_code) {

	if (!rsa_netas) RSA_free(rsa_netas);
	if (!rsa_client) RSA_free(rsa_client);
	
	if (session_key) free(session_key);
	if (fd_license) fclose(fd_license);
	if (license) free(license);
	
	exit(exit_code);
}

void load_client_private_key() {
	byte fname[_MAX_PATH];

	rsa_client = load_key(fullname(pri_client, fname), true, false);
	if (!rsa_client) {
		print_last_error();
		exit_program(1);
	}
	write_publickey(fullname(pub_client, fname), rsa_client);
}

void load_netas_public_key() {
	byte fname[_MAX_PATH];

	rsa_netas = load_key(fullname(pub_netas, fname), false, true);
	if (!rsa_netas) {
		print_last_error();
		exit_program(2);
	}
	
}

void create_session_key() {

	generate_random_key(&session_key, 16);
	if (!session_key) 
		exit_program(40);

	int size = RSA_size(rsa_netas);
	byte *enc_session_key = malloc(size);

	memset(enc_session_key, 0, size);

	int elen = public_encrypt(strlen(session_key), session_key, enc_session_key, rsa_netas);
	if (!elen) {
		free(enc_session_key);
		exit_program(41);
	}
	
	byte *b64_session_key = NULL;
	encode_b64(enc_session_key, elen, &b64_session_key);
	if (!b64_session_key) {
		free(enc_session_key);
		exit_program(42);
	}

	free(enc_session_key);	
	
	fputs("---BEGIN SESSION KEY---\n", fd_license);
	b64_write_to_file(b64_session_key, fd_license);
	fputs("---END SESSION KEY---\n", fd_license);
		
	free(b64_session_key);
		
}

void add_client_public_key() {
	byte fname[_MAX_PATH];

	byte *public_client = load_from_file(fullname(pub_client, fname));
	if (!public_client)
		exit_program(5);
		
	fputs(public_client, fd_license);
	free(public_client);

}

void add_client_license_info() {
	
	byte *clr_license = NULL;
	license_to_string(license, &clr_license);
	if (!clr_license)
		exit_program(61);
	
	byte *enc_license = NULL;
	int elen = crypt(clr_license, strlen(clr_license), &enc_license, session_key, encrypt);
	if (!elen || !enc_license) {
		free(clr_license);
		exit_program(62);
	}
	
	free(clr_license);
		
	byte *b64_license = NULL;
	encode_b64(enc_license, elen, &b64_license);
	if (!b64_license) {
		free(enc_license);
		exit_program(63);
	}
	
	free(enc_license);
	
	fputs("---BEGIN LICENSE---\n", fd_license);
	b64_write_to_file(b64_license, fd_license);
	fputs("---END LICENSE---\n", fd_license);
	
	free(b64_license);
}

void usage() {

	printf("usage:\nlicense_public.exe <full_path_name_of_the_pem_files> <version_of_the_nipps> <phone_service_name:version [phone_service_name_2:version2 ... ]>");

	exit_program(-1);

}

int main(int argc, byte **argv)
{
	byte fname[_MAX_PATH];

	if (argc < 3)
		usage();

	memset(path_name, 0, _MAX_PATH);
	strcpy(path_name, argv[1]);

	load_client_private_key();

	load_netas_public_key();
	
	fd_license = fopen(fullname(client_lic, fname), "w");	
	if (!fd_license)
		exit_program(3);
	
	create_session_key();
		
	add_client_public_key();	
	
	license = init_license(argc, argv);
	if (!license)
		exit_program(6);
		
	add_client_license_info();
		
	exit_program(0);
}
