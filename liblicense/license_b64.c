#include <string.h>
#include "license.h"

const byte hexc[16] = 
	{ '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

const byte b64[] = 
	{ 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P'
	, 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f'
	, 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v'
	, 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/' };

int b64i(byte c) {
	int i = 0;
	
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

int __stdcall base64_decode(byte *source, byte **target) {

	if (!source || !target)
		return 0;
		
	int i = 0, 
		j = 0, 
		slen = strlen((const char *)source),
		tlen = (slen * 3 / 4);
	
	if (slen % 4)
		return 0;
	
	if (!(*target))
		*target = malloc(tlen);
		
	memset(*target, 0, tlen);
	
	if (source[slen - 1] == '=') {
		source[slen - 1] = 0;
		tlen--;
		if (source[slen - 2] == '=') {
			source[slen - 2] = 0;
			tlen--;
		}
	}
		
	while (i <= slen - 4) {
		(*target)[j] = (b64i(source[i]) << 2) + (b64i(source[i + 1]) >> 4);
		(*target)[j + 1] = ((b64i(source[i + 1]) & 0xf) << 4) + (b64i(source[i + 2]) >> 2);
		(*target)[j + 2] = ((b64i(source[i + 2]) & 0x3) << 6) + b64i(source[i + 3]);
		i += 4;
		j += 3;
	}
	
	return tlen;
}

byte *__stdcall base64_encode(byte *source, int slen, byte **target) {
	if (!source || !target)
		return NULL;
		
	int i = 0, 
		j = 0, 
		tlen = 1 + (slen + 3 - slen % 3) * 4 / 3;
		
	reallocate(target, tlen);

	while (i <= slen - 3) {
		(*target)[j] = b64[source[i] >> 2];
		(*target)[j + 1] = b64[((source[i] & 0x3) << 4) + (source[i + 1] >> 4)];
		(*target)[j + 2] = b64[((source[i + 1] & 0xf) << 2) + (source[i + 2] >> 6)];
		(*target)[j + 3] = b64[source[i + 2] & 0x3f];
		i += 3;
		j += 4;
	}
	if (slen % 3 == 2) {
		(*target)[j] = b64[source[i] >> 2];
		(*target)[j + 1] = b64[((source[i] & 0x3) << 4) + (source[i + 1] >> 4)];
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

void __stdcall base64_write_to_file(byte *b64, FILE *fd) {
	
	if (!b64 || !fd)
		return;
		
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

byte *__stdcall hex_encode(byte *source, int slen, byte **target) {
	int i = 0, 
		c,
		tlen = 1 + slen * 2;
	
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

