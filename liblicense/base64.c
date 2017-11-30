#include "ossllib.h"

const unsigned char hexc[16] = 
	{ '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 
        'D', 'E', 'F' };

const unsigned char b64[] = 
	{ 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 
        'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 
        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 
        'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/' };

int b64toi(const unsigned char c) {
	
        if (c == '+')
		return 62;
	
	if (c == '/')
		return 63;
		
	if (c >= '0' && c <= '9')
		return 52 + c - '0';
		
	if (c >= 'a' && c <= 'z')
		return 26 + c - 'a';
		
	return c - 'A';

}

void generate_random_key(int klen, unsigned char **random_key) {

	if (!random_key)
	        exit_on_error(EB64FAIL);

	if (klen < 16)
		klen = 16;

	if (!*random_key)
		free(*random_key);

	*random_key = malloc(klen + 1);
	memset(*random_key, 0, klen + 1);

	int i;
	for (i = 0; i < klen; i++)
		(*random_key)[i] = b64[rand() % 64];

}

int base64_decode(const unsigned char *source, unsigned char **target) {

	if (!source || !target)
		exit_on_error(EB64FAIL);
		
	int i = 0, 
		j = 0, 
		slen = strlen((const char *)source),
		tlen = (slen * 3 / 4);
	
	if (slen % 4)
		exit_on_error(EB64FAIL);
	
	if (!(*target))
		*target = malloc(tlen);
		
	memset(*target, 0, tlen);
	
	if (source[slen - 2] == '=')
		tlen--;
	if (source[slen - 1] == '=')
		tlen--;
		
	while (i <= slen - 4) {
		unsigned char b0 = source[i],
				b1 = source[i+1],
				b2 = source[i+2] == '=' ? 0 : source[i+2],
				b3 = source[i+3] == '=' ? 0 : source[i+3];
		(*target)[j] = (b64toi(b0) << 2) + (b64toi(b1) >> 4);
		(*target)[j + 1] = ((b64toi(b1) & 0xf) << 4) + 
                                (b64toi(b2) >> 2);
		(*target)[j + 2] = ((b64toi(b2) & 0x3) << 6) + b64toi(b3);
		i += 4;
		j += 3;
	}
	
	return tlen;
}

unsigned char *base64_encode(const unsigned char *source, const int slen, 
                                unsigned char **target) {

        if (!source || !slen || !target)
		exit_on_error(EB64FAIL);
		
	int i = 0, 
		j = 0, 
		tlen = 1 + (slen + 3 - slen % 3) * 4 / 3;
		
	reallocate(target, tlen);

	while (i <= slen - 3) {
		(*target)[j] = b64[source[i] >> 2];
		(*target)[j + 1] = b64[((source[i] & 0x3) << 4) + 
                                (source[i + 1] >> 4)];
		(*target)[j + 2] = b64[((source[i + 1] & 0xf) << 2) + 
                                (source[i + 2] >> 6)];
		(*target)[j + 3] = b64[source[i + 2] & 0x3f];
		i += 3;
		j += 4;
	}
	if (slen % 3 == 2) {
		(*target)[j] = b64[source[i] >> 2];
		(*target)[j + 1] = b64[((source[i] & 0x3) << 4) + 
                                (source[i + 1] >> 4)];
		(*target)[j + 2] = b64[(source[i + 1] & 0xf) << 2];
		(*target)[j + 3] = '=';
	}
	else if (slen % 3 == 1) {
		(*target)[j] = b64[source[i] >> 2];
		(*target)[j + 1] = b64[(source[i] & 0x3) << 4];
		(*target)[j + 2] = '=';
		(*target)[j + 3] = '=';
	}
	return *target;
}

void base64_write_to_file(const unsigned char *b64, FILE *fd) {
	
	if (!b64 || !fd)
		exit_on_error(EB64WRFL);
		
	int l = strlen((const char *)b64),
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

unsigned char *hex_encode(const unsigned char *source, const int slen, 
                        unsigned char **target) {

	int i = 0, 
		c,
		tlen = 1 + slen * 2;
	
	if (!source || !slen)
	        exit_on_error(EB64FAIL);

	if (!(*target))
		*target = malloc(tlen);
		
	memset(*target, 0, tlen);
	
	while (i < slen) {
		c = (int) source[i];
		(*target)[2 * i] = hexc[c >> 4];
		(*target)[ 2 * i + 1] = hexc[c & 0xf];
		i++;
	}
	
	return *target;
}

