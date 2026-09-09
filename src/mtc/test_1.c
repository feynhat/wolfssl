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
	size_t i, index = 2034, start = 1024, end = 2036, n_proofs;
	Entry entries[2036];
	byte *inclusion_proof = NULL;
	char rolling[20000], hashstring[2 * SHA256_DIGEST_SIZE + 1] = {0};

	for (i = 0; i < end; ++i) {
		entries[i].data = malloc(1);
		*(entries[i].data) = i;
		entries[i].length = 1;
	}

	n_proofs = subtree_inclusion_proof(&inclusion_proof, entries, index, start, end);
	sprintf(rolling, "%d [%d, %d)", index, start, end);
	printf("length of proof: %d\n", n_proofs);
	for (i = 0; i < n_proofs; ++i) {
		hash_to_str(hashstring, inclusion_proof + i*SHA256_DIGEST_SIZE);
		strcat(rolling, " ");
		strcat(rolling, hashstring);
	}
	strcat(rolling, "\n");
	printf("%s", rolling);

	free(inclusion_proof);

	for (i = 0; i < end; ++i) {
		free(entries[i].data);
	}
}
