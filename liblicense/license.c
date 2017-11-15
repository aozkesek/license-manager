#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <memory.h>
#include <string.h>

#include "license.h"

void __stdcall lib_initialize() {
        ERR_load_crypto_strings();
        OpenSSL_add_all_algorithms();
        OPENSSL_config(NULL);
        srand(time(0));
}

void __stdcall lib_finalize() {
        EVP_cleanup();
        CRYPTO_cleanup_all_ex_data();
        ERR_free_strings();
}

void __stdcall exit_on_error_m(const char *file_name, const char *function_name, const int line_number) {
        printf("vvv program is stopped on error vvv\n(%s(%d):%s)\n", file_name, line_number, function_name);
        program_exit(-0x1000);
}

void __stdcall print_last_error_m(const char *file_name, const char *function_name, const int line_number) {
        char last_error[4000];
        ERR_error_string(ERR_get_error(), last_error);
        printf("vvv crypto last error vvv\n(%s(%d):%s)\n\t%s\n", file_name, line_number, function_name, last_error);
}

PLICENSE_STRUCT __stdcall license_init(int argc, const char **argv) {
        PLICENSE_STRUCT license;
        PSERVICE_STRUCT nipps;

        if (!argc || !argv)
                exit_on_error();

        nipps = malloc(sizeof(SERVICE_STRUCT) * argc - 3);

        int i = 3, k = 0;
        char *p = NULL;
        for (; i < argc; i++) {
                p = strstr(argv[i], ":");
                if (!p)
                        continue;

                nipps[i - 3].service_name = malloc(p - argv[i] + 1);
                memset(nipps[i - 3].service_name, 0, p - argv[i] + 1);
                strncpy(nipps[i - 3].service_name, argv[i], p - argv[i]);

                nipps[i - 3].service_version = malloc(strlen(p));
                memset(nipps[i - 3].service_version, 0, strlen(p));
                strcpy(nipps[i - 3].service_version, p + 1);

                k++;
        }

        license = malloc(sizeof(LICENSE_STRUCT));

        license->license_acquirer = "CLIENT";
        license->license_service_size = k;
        license->license_version = malloc(strlen(argv[2]) + 1);
        memset(license->license_version, 0, strlen(argv[2]) + 1);
        strcpy(license->license_version, argv[2]);
        license->license_issuer = "TECHNICIAN";
        license->license_services = nipps;

        return license;
}

void __stdcall license_free(PLICENSE_STRUCT plicense) {

	if (!plicense)
	        exit_on_error();

	free(plicense->license_services);
	free(plicense);
}

int __stdcall license_size(PLICENSE_STRUCT plicense) {
	int len = 0;
	if (!plicense)
	        exit_on_error();

	char *license_json = "{'Version':'','LicensedTo':'','IssuedBy':'','Services':[]}";
	char *license_services_json = "{'Name':'','Version':''},";

	len += strlen(plicense->license_issuer);
	len += strlen(plicense->license_acquirer);
	len += strlen(plicense->license_version);

	len += 2; //plicense->Service_Count

	int i = 0;
	for(; i < plicense->license_service_size; i++) {
		len += strlen(plicense->license_services[i].service_name);
		len += strlen(plicense->license_services[i].service_version);
	}

	return len + strlen(license_json) + plicense->license_service_size * strlen(license_services_json);
}

char *__stdcall license_to_json_string(PLICENSE_STRUCT plicense, char **slicense) {

	if (!plicense || !slicense)
		exit_on_error();

	int slen = license_size(plicense);
	if (!(*slicense))
		*slicense = malloc((slen));
	memset(*slicense, 0, slen);

	sprintf(*slicense,
		"{\"Version\":\"%s\",\"LicensedTo\":\"%s\",\"IssuedBy\":\"%s\",\"Services\":["
		, plicense->license_version
		, plicense->license_acquirer
		, plicense->license_issuer
		);

	int i, pos = strlen(*slicense);

	for (i = 0; i < plicense->license_service_size; i++)
	{
		sprintf(*slicense + pos
			, "{\"Name\":\"%s\",\"Version\":\"%s\"}"
			, plicense->license_services[i].service_name
			, plicense->license_services[i].service_version);
		pos = strlen(*slicense) ;
		if (i < plicense->license_service_size - 1)
			sprintf(*slicense + pos++, ",");
	}

	pos = strlen(*slicense);
	sprintf(*slicense + pos, "]}");

	return *slicense;
}

void __stdcall license_print(PLICENSE_STRUCT plicense) {
 	if (!plicense)
		exit_on_error();
	char *buffer = NULL;
	printf("\n%s\n", license_to_json_string(plicense, &buffer));
	free(buffer);
}

byte *__stdcall reallocate(byte **b, int blen) {
	if (!b)
		exit_on_error();

	if(*b)
		free(*b);
	*b = malloc(blen);
	memset(*b, 0, blen);
	return *b;
}

byte *__stdcall load_from_file(const char *fname) {

	FILE *file = fopen(fname, "r");
	if (!file)
		exit_on_error();

	if (fseek(file, 0, SEEK_END)) {
		fclose(file);
		exit_on_error();
	}

	int flen = ftell(file);
	rewind(file);

	byte *message = malloc(flen + 1);

	fread(message, flen, 1, file);

	fclose(file);

	message[flen] = 0;

	return message;
}

char *__stdcall sub_value_extract_trim(const char *lic_client, const char *begin_title, const char *end_title) {

	char *p_begin_title = strstr(lic_client, begin_title);
	if (!p_begin_title)
		exit_on_error();

	char *p_end_title = strstr(lic_client, end_title);
	if (!p_end_title)
		exit_on_error();

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

char *__stdcall sub_value_extract(const char *lic_client, const char *begin_title, const char *end_title) {

	char *p_begin_title = strstr(lic_client, begin_title);
	if (!p_begin_title)
	        exit_on_error();

	char *p_end_title = strstr(lic_client, end_title);
	if (!p_end_title)
	        exit_on_error();

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

#ifdef __WIN32

void initialize();
void finalize();

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {

	switch (fdwReason) {
	case DLL_PROCESS_ATTACH:
		initialize();
		break;

	case DLL_PROCESS_DETACH:
		finalize();
		break;
	}

	return TRUE;
}
#endif
