#include <ctime>
#include <stdio.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>

static char base32_table[33] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

size_t base32_encode(char* dst, unsigned char* src, size_t len) {
	unsigned int output = 0;
	int bitcount = 0;
	int res = 0;
	auto outidx = 0;

	while (len>0) {
		output <<= 8;
		output |= (unsigned char)*src;
		bitcount += 8;
		src++;
		do {
			unsigned int idx = (output >> (bitcount-5)) & 0x1f;
			dst[outidx++] = base32_table[idx];
			bitcount -= 5;
			res++;
		} while (bitcount >= 5);
		len--;
	}


	if (bitcount > 0) {
		output <<= 8;
		output |= 0;
		bitcount += 8;
		unsigned int idx = (output >> (bitcount-5)) & 0x1f;
		dst[outidx++] = base32_table[idx];
		bitcount -= 5;
		res++;
	}
	dst[outidx++] = 0;

	return res;
}

size_t base32_decode(unsigned char* dst, const char* src) {
	unsigned int output = 0;
	int bitcount = 0;
	int res = 0;
	int padding_bits = 0;

	while(*src != 0) {
		char* ptr = strchr(base32_table, *src);
		if (ptr != NULL) {
			output <<= 6;
			size_t idx = ptr - base32_table;
			output |= idx;
			bitcount += 6;
		}
		if (bitcount == 24 || ptr == NULL) {
			while (bitcount > padding_bits) {
				*dst = (unsigned char)(output >> 16) & 0xff;
				output <<= 8;
				dst++;
				bitcount -= 8;
				res++;
			}
		}
		src++;
	}
	return res;
}

void rmemcpy(void* dst, const void* src, int len) {
    auto cdst = (unsigned char*)dst;
    auto csrc = (const unsigned char*)src;
    csrc += len;
    for (; len>0 ; len--) 
        *cdst++ = *--csrc;   
}

int generate_HOTP(unsigned char* secret, int secret_len, int counter){
	unsigned char buffer[8];

    int64_t i64 = counter;
    rmemcpy(buffer, &i64, 8);

	unsigned char* hmac_result = HMAC(EVP_sha1(), secret, secret_len, buffer, 8, NULL, NULL);

	int offset = hmac_result[19] & 0xf;
	unsigned int bin_code = (hmac_result[offset]  & 0x7f) << 24
		| (hmac_result[offset+1]) << 16
		| (hmac_result[offset+2]) <<  8
		| (hmac_result[offset+3]);
	
	int code = bin_code % 1000000;
	return code;
}