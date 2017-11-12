#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <memory.h>
#include <string.h>

#include "license.h"

PLICENSE_STRUCT __stdcall license_init(int argc, const char **argv) {
    PLICENSE_STRUCT license;
    PNIPPS_STRUCT nipps;

	if (!argc || !argv)
		return NULL;

        nipps = malloc(sizeof(NIPPS_STRUCT) * argc - 3);

	int i = 3, k = 0;
	char *p = NULL;
	for (; i < argc; i++) {
		p = strstr(argv[i], ":");
		if (!p)
			continue;

		nipps[i - 3].Name = malloc(p - argv[i] + 1);
		memset(nipps[i - 3].Name, 0, p - argv[i] + 1);
		strncpy(nipps[i - 3].Name, argv[i], p - argv[i]);

		nipps[i - 3].Version = malloc(strlen(p));
		memset(nipps[i - 3].Version, 0, strlen(p));
		strcpy(nipps[i - 3].Version, p + 1);

		k++;
	}

    license = malloc(sizeof(LICENSE_STRUCT));

    license->Licensed_To = "CLIENT";
    license->Service_Count = k;
    license->Version = malloc(strlen(argv[2]) + 1);
    memset(license->Version, 0, strlen(argv[2]) + 1);
    strcpy(license->Version, argv[2]);
	license->Issued_By = "TECHNICIAN";
    license->Services = nipps;

    return license;
}

void __stdcall license_free(PLICENSE_STRUCT plicense) {

	if (!plicense)
		return;
	free(plicense->Services);
	free(plicense);
}

int __stdcall license_size(PLICENSE_STRUCT plicense) {
	int len = 0;
	if (!plicense)
		return 0;

	char *license_json = "{'Version':'','LicensedTo':'','IssuedBy':'','Services':[]}";
	char *license_services_json = "{'Name':'','Version':''},";

	len += strlen(plicense->Issued_By);
	len += strlen(plicense->Licensed_To);
	len += strlen(plicense->Version);

	len += 2; //plicense->Service_Count

	int i = 0;
	for(; i < plicense->Service_Count; i++) {
		len += strlen(plicense->Services[i].Name);
		len += strlen(plicense->Services[i].Version);
	}

	return len + strlen(license_json) + plicense->Service_Count * strlen(license_services_json);
}

char *__stdcall license_to_json_string(PLICENSE_STRUCT plicense, char **slicense) {

	if (!plicense || !slicense)
		return NULL;

	int slen = license_size(plicense);
	if (!(*slicense))
		*slicense = malloc((slen));
	memset(*slicense, 0, slen);

	sprintf(*slicense,
		"{\"Version\":\"%s\",\"LicensedTo\":\"%s\",\"IssuedBy\":\"%s\",\"Services\":["
		, plicense->Version
		, plicense->Licensed_To
		, plicense->Issued_By
		);

	int i, pos = strlen(*slicense);

	for (i = 0; i < plicense->Service_Count; i++)
	{
		sprintf(*slicense + pos
			, "{\"Name\":\"%s\",\"Version\":\"%s\"}"
			, plicense->Services[i].Name
			, plicense->Services[i].Version);
		pos = strlen(*slicense) ;
		if (i < plicense->Service_Count - 1)
			sprintf(*slicense + pos++, ",");
	}

	pos = strlen(*slicense);
	sprintf(*slicense + pos, "]}");

	return *slicense;
}

void __stdcall license_print(PLICENSE_STRUCT plicense) {
 	if (!plicense)
		return;
	char *buffer = NULL;
    printf("\n%s\n", license_to_json_string(plicense, &buffer));
	free(buffer);
}

byte *__stdcall reallocate(byte **b, int blen) {
	if (!b)
		return NULL;

	if(*b)
		free(*b);
	*b = malloc(blen);
	memset(*b, 0, blen);
	return *b;
}

byte *__stdcall load_from_file(const char *fname) {

	FILE *file = fopen(fname, "r");
	if (!file)
		return NULL;

	if (fseek(file, 0, SEEK_END)) {
		fclose(file);
		return NULL;
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
		return NULL;

	char *p_end_title = strstr(lic_client, end_title);
	if (!p_end_title)
		return NULL;

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
		return NULL;

	char *p_end_title = strstr(lic_client, end_title);
	if (!p_end_title)
		return NULL;

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
