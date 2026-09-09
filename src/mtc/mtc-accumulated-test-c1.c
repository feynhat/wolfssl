#define WOLFSSL_USE_OPTIONS_H 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wolfssl/wolfcrypt/sha256.h>

#include "mtc.h"
#include "bit.h"

typedef unsigned char byte;

int main(void)
{
	size_t i = 0, start = 0, end = 0;
	Entry entries[130];
	Sha256 sha256;
	byte subtree_hash[SHA256_DIGEST_SIZE];
	char rolling[100], hashstring[2 * SHA256_DIGEST_SIZE + 1] = {0};

	for (i = 0; i < 130; ++i) {
		entries[i].data = malloc(1);
		*entries[i].data = i;
		entries[i].length = 1;
	}
	wc_InitSha256(&sha256);

	for (end = 1; end <= 130; ++end) {
		for (start = 0; start < end; ++start) {
			if (is_valid_subtree(start, end)) {
				mt_hash(subtree_hash, entries, start, end);
				hash_to_str(hashstring, subtree_hash);
				//printf("[%d, %d) %s\n", start, end, hashstring);
				sprintf(rolling, "[%d, %d) %s\n", start, end, hashstring);
				wc_Sha256Update(&sha256, rolling, strlen(rolling));
			}
		}
	}
	wc_Sha256Final(&sha256, rolling);
	print_full_hash(rolling);

	for (i = 0; i < 130; ++i) {
		free(entries[i].data);
	}
	return 0;
}
