#include "ossllib.h"

#define b64toi(c) ( \
	c=='+' ? 62 : \
	c=='/' ? 63 : \
	c>='0' && c<='9' ? 52+c-'0' : \
	c>='a' && c<='z' ? 26+c-'a' : c-'A' \
)

const char hexc[16] =
	{'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};

const char b64[] =
	{'A','B','C','D','E','F','G','H','I','J','K','L','M',
         'N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
         'a','b','c','d','e','f','g','h','i','j','k','l','m',
         'n','o','p','q','r','s','t','u','v','w','x','y','z',
         '0','1','2','3','4','5','6','7','8','9','+','/' };

int gen_session_key(int klen, char **key) {

	if (!key)
	        on_error(EB64FAIL);

	if (klen < 16)
		klen = 16;

	if (klen > MAX_SESSION_KSIZE)
		klen = MAX_SESSION_KSIZE;

	reallocate(key, klen+1);

	for (int i = 0; i < klen; i++)
		(*key)[i] = b64[rand() % 64];

	return klen;
}

int base64_decode(const char *src, const int srclen, char **target) {

	if (!src || !target || 	srclen % 4)
		on_error(EB64FAIL);
		
	int i = 0, j = 0, tlen = (srclen * 3 / 4);
	char b0, b1, b2, b3;
	
	if (src[srclen - 2] == '=')
		tlen--;
	if (src[srclen - 1] == '=')
		tlen--;

	reallocate(target, tlen+1);
		
	while (i <= srclen - 4) {
		b0 = src[i];
		b1 = src[i+1];
		b2 = src[i+2] == '=' ? 0 : src[i+2];
		b3 = src[i+3] == '=' ? 0 : src[i+3];
		
		(*target)[j] = (b64toi(b0) << 2) + (b64toi(b1) >> 4);
		(*target)[j + 1] = ((b64toi(b1) & 0xf) << 4) + (b2 ? (b64toi(b2) >> 2) : 0);
		(*target)[j + 2] = b2 && b3 ? (((b64toi(b2) & 0x3) << 6) + b64toi(b3)) : 0;
		i += 4;
		j += 3;
	}
	
	return tlen;
}

char *base64_encode(const char *src, const int srclen, char **target) {

        if (!src || !srclen || !target)
		on_error(EB64FAIL);
		
	int i = 0, j = 0, tlen = 1 + (srclen + 3 - srclen % 3) * 4 / 3;
		
	reallocate(target, tlen);

	unsigned char c1, c2, c3;
	while (i <= srclen - 3) {
		c1 = (unsigned char)src[i];
		c2 = (unsigned char)src[i+1];
		c3 = (unsigned char)src[i+2];
		(*target)[j] = b64[c1 >> 2];
		(*target)[j + 1] = b64[((c1 & 0x3) << 4) + (c2 >> 4)];
		(*target)[j + 2] = b64[((c2 & 0xf) << 2) + (c3 >> 6)];
		(*target)[j + 3] = b64[c3 & 0x3f];
		i += 3;
		j += 4;
	}
	if (srclen % 3 == 2) {
		c1 = (unsigned char)src[i];
		c2 = (unsigned char)src[i+1];
		(*target)[j] = b64[c1 >> 2];
		(*target)[j + 1] = b64[((c1 & 0x3) << 4) + (c2 >> 4)];
		(*target)[j + 2] = b64[(c2 & 0xf) << 2];
		(*target)[j + 3] = '=';
	}
	else if (srclen % 3 == 1) {
		c1 = (unsigned char)src[i];
		(*target)[j] = b64[c1 >> 2];
		(*target)[j + 1] = b64[(c1 & 0x3) << 4];
		(*target)[j + 2] = '=';
		(*target)[j + 3] = '=';
	}
	return *target;
}

void base64_write_to_file(const char *b64, FILE *fd) {
	
	if (!b64 || !fd)
		on_error(EB64WRFL);
		
	int l = strlen(b64),
		r = l % 64,
		k = (l - r) / 64,
		i = 0;
	
	while(i < k) {
		fwrite(b64 + (i * 64), 1, 64, fd);
		fputs("\n", fd);
		i++;
	}

	fwrite(b64 + (i * 64), 1, r, fd);
	fputs("\n", fd);
	
}

char *hex_encode(const char *src, const int srclen, char **target) {
	
	if (!src || !srclen)
	        on_error(EB64FAIL);

	int i = 0, c, tlen = 1 + srclen * 2;
	reallocate(target, tlen);
	
	while (i < srclen) {
		c = (int) src[i];
		(*target)[2 * i] = hexc[c >> 4];
		(*target)[2 * i + 1] = hexc[c & 0xf];
		i++;
	}
	
	return *target;
}

void base64_selftest()
{
	char *sesskey = NULL;
	char *b64buff = NULL;
	char *tmpbuff = NULL;

	gen_session_key(64,&sesskey);
	printf("Session key tested  : (len=%d) %s\n", strlen(sesskey), sesskey);

	base64_encode(sesskey, strlen(sesskey), &b64buff);
	printf("Base64 encode tested: (len=%d) %s\n", strlen(b64buff), b64buff);

	base64_decode(b64buff, strlen(b64buff), &tmpbuff);
	printf("Base64 decode tested: (len=%d) %s\n", strlen(tmpbuff), tmpbuff);

	if (strcmp(sesskey, tmpbuff)) {
		printf("Base64 test failed!\n");
		goto cleanup;
	}

	hex_encode(sesskey, strlen(sesskey), &tmpbuff);
	printf("Hex encode tested   : (len=%d) %s\n", strlen(tmpbuff), tmpbuff);

	printf("Base64 test passed.\n");

cleanup:
	free(sesskey);
	free(b64buff);
	free(tmpbuff);
}
