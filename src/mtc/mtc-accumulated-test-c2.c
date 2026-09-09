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
	size_t i, index = 0, start = 0, end = 0, n_proofs;
	Entry entries[130];
	Sha256 sha256;
	byte proof_hash[SHA256_DIGEST_SIZE], *inclusion_proof = NULL, space = ' ';
	char rolling[20000], hashstring[2 * SHA256_DIGEST_SIZE + 1] = {0};

	for (i = 0; i < 130; ++i) {
		entries[i].data = malloc(1);
		*(entries[i].data) = i;
		entries[i].length = 1;
	}
	wc_InitSha256(&sha256);

	for (end = 1; end <= 130; ++end) {
		for (start = 0; start < end; ++start) {
			if (is_valid_subtree(start, end)) {
				for (index = start; index < end; ++index) {
					n_proofs = subtree_inclusion_proof(&inclusion_proof, entries, index, start, end);
					sprintf(rolling, "%d [%d, %d)", index, start, end);
					for (i = 0; i < n_proofs; ++i) {
						hash_to_str(hashstring, inclusion_proof + i*SHA256_DIGEST_SIZE);
						strcat(rolling, " ");
						strcat(rolling, hashstring);
					}
					strcat(rolling, "\n");
					//printf("%s", rolling);
					wc_Sha256Update(&sha256, rolling, strlen(rolling));
				}
			}
		}
	}
	wc_Sha256Final(&sha256, rolling);
	print_full_hash(rolling);

	free(inclusion_proof);

	for (i = 0; i < 130; ++i) {
		free(entries[i].data);
	}
}
