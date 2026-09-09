#define WOLFSSL_USE_OPTIONS_H 1

#include <string.h>

#include <wolfssl/wolfcrypt/sha256.h>

#ifdef WOLFSSL_MTC_EVALUATOR_ONLY
    typedef struct {
        byte *data;
        size_t length;
    } Entry;
    #define MTC_EVALUATOR_SCOPE static
#else
    #include <ctype.h>
    #include <stdio.h>
    #include <stdlib.h>

    #include "mtc.h"
    #include "bit.h"

    #define MTC_EVALUATOR_SCOPE
#endif

typedef unsigned char byte;

#ifndef WOLFSSL_MTC_EVALUATOR_ONLY
size_t merkle_split(size_t n)
{
	size_t k = 1;

	while (k << 1 < n)
		k <<= 1;

	return k;
}

void mt_hash(byte out[], const Entry entries[], size_t start, size_t end)
{
	// Assume [start, end) is a valid subtree
	// Assume out has enough storage
	int n = end - start, k;
	byte left[SHA256_DIGEST_SIZE], right[SHA256_DIGEST_SIZE];

	if (n == 1) {
		hash_leaf(out, entries + start);
	} else {
		k = merkle_split(n);
		mt_hash(left, entries, start, start + k);
		mt_hash(right, entries, start+k, end);
		hash_internal(out, left, right);
	}

	//TreeNode *tree = malloc(sizeof(TreeNode));
	//build_mt_subtree(tree, entries, start, end);
	//memcpy(out, tree->data, SHA256_DIGEST_SIZE);
	//free_subtree(tree);
}

size_t subtree_inclusion_proof_size(size_t index, size_t start, size_t end)
{
	size_t n = end - start, k;
	if (n == 1)
		return 0;

	k = merkle_split(n);

	if (index < start + k)
		return 1 + subtree_inclusion_proof_size(index, start, start + k);

	return 1 + subtree_inclusion_proof_size(index, start + k, end);
}

size_t subtree_inclusion_proof(byte **proof, const Entry *entries, size_t index, size_t start, size_t end)
{
	*proof = (byte *)malloc(subtree_inclusion_proof_size(index, start, end) * SHA256_DIGEST_SIZE);
	return subtree_inclusion_proof_allocated(proof, entries, index, start, end);
}

size_t subtree_inclusion_proof_allocated(byte **proof, const Entry *entries, size_t index, size_t start, size_t end)
{
	// Assume [start, end) is a valid subtree
	// Assume **proof has been allocated enough memory to contain the inclusion proof
	size_t m = index - start, n = end - start, proof_length;
	size_t k;

	if (end - start == 1) {
		return 0; // inclusion proof for leaves is empty
	}

	k = merkle_split(n);

	if (m < k) {
		proof_length = subtree_inclusion_proof_allocated(proof, entries, index, start, start + k);
		mt_hash(*proof + proof_length*SHA256_DIGEST_SIZE, entries, start + k, end);
		return proof_length + 1;
	} else {
		proof_length = subtree_inclusion_proof_allocated(proof, entries, index, start+k, end);
		mt_hash(*proof + proof_length*SHA256_DIGEST_SIZE, entries, start, start+k);
		return proof_length + 1;
	}
}

size_t subtree_proof(byte **proof, const Entry entries[], size_t n, size_t start, size_t end)
{
	return subtree_subproof(proof, entries, 0, n, start, end, 1);
}

size_t subtree_subproof(byte **proof, const Entry entries[], size_t zero, size_t n, size_t start, size_t end, unsigned known)
{
	size_t k = 1, proof_length;

	if (!start && end == n) {
		if (known) {
			return 0;
		} else {
			*proof = realloc(*proof, SHA256_DIGEST_SIZE);
			mt_hash(*proof, entries, zero, zero+n);
			return 1;
		}
	}
	// n > 1
	while ((k << 1) < n)
		k <<= 1;

	if (end <= k) {
		proof_length = subtree_subproof(proof, entries, zero, k, start, end, known);
		*proof = realloc(*proof, (proof_length + 1)*SHA256_DIGEST_SIZE);
		mt_hash(*proof + proof_length*SHA256_DIGEST_SIZE, entries, zero+k, zero+n);
		return proof_length + 1;
	} else if (k <= start) {
		proof_length = subtree_subproof(proof, entries, zero+k, n-k, start - k, end - k, known);
		*proof = realloc(*proof, (proof_length + 1)*SHA256_DIGEST_SIZE);
		mt_hash(*proof + proof_length*SHA256_DIGEST_SIZE, entries, zero, zero+k);
		return proof_length + 1;
	} else {
		proof_length = subtree_subproof(proof, entries, zero+k, n-k, 0, end-k, 0);
		*proof = realloc(*proof, (proof_length + 1)*SHA256_DIGEST_SIZE);
		mt_hash(*proof + proof_length*SHA256_DIGEST_SIZE, entries, zero, zero+k);
		return proof_length + 1;
	}
}

int hex_digit(char c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

void read_hash(byte hash[])
{
	char encoded[SHA256_DIGEST_SIZE * 2 + 1];
	size_t i;
	int hex0, hex1;

	scanf("%s", encoded);
	for (i = 0; i < SHA256_DIGEST_SIZE; ++i) {
		hex1 = hex_digit(encoded[i * 2]);
		hex0 = hex_digit(encoded[i * 2 + 1]);
		hash[i] = (byte)((hex1 << 4) | hex0);
	}
}

size_t read_inclusion_proof(byte **proof)
{
	byte *data = NULL;
	/* initialized to NULL because, we call realloc on data without checking if
	* it was allocated */
	size_t data_length = 0, data_capacity = 0, proof_length;
	int hex0, hex1=-1;
	int c;
	byte *resized_data;
	size_t new_capacity;

	while ((c = getchar()) != EOF) {
		hex0 = hex_digit((char)c);
		if (hex1 < 0) {
			hex1 = hex0;
			continue;
		}

		if (data_length == data_capacity) {
			if (data_capacity == 0) {
				new_capacity = SHA256_DIGEST_SIZE * 4;
			} else {
				new_capacity = data_capacity * 2;
			}
			resized_data = realloc(data, new_capacity);
			if (resized_data == NULL) {
				exit(1);
			}
			data = resized_data;
			data_capacity = new_capacity;
		}
		data[data_length++] = (byte)((hex1 << 4) | hex0);
		hex1 = -1;
	}

	if (hex1 >= 0) {
		printf("invalid inclusion proof format: odd number of hexes\n");
	}
	*proof = data;
	proof_length = data_length / SHA256_DIGEST_SIZE;
	return proof_length;
}

void hash_to_str(char *out, const byte hash[])
{
	size_t i;

	for (i = 0; i < SHA256_DIGEST_SIZE; ++i) {
		sprintf(out + 2*i, "%02x", hash[i]);
	}
	out[2 * SHA256_DIGEST_SIZE] = '\0';
}

void print_full_hash(const byte hash[SHA256_DIGEST_SIZE])
{
	size_t i;

	for (i = 0; i < SHA256_DIGEST_SIZE; ++i) {
		printf("%02x", hash[i]);
	}
	putchar('\n');
}

void build_mt(TreeNode *tree, const Entry entries[], size_t length)
{
	build_mt_subtree(tree, entries, 0, length);
}

void build_mt_subtree(TreeNode *tree, const Entry entries[], size_t start, size_t end)
{
	size_t k;
	size_t length = end - start;

	tree->left = NULL;
	tree->right = NULL;

	if (length == 1) {
		hash_leaf(tree->data, entries + start);
		return;
	}

	k = merkle_split(length);

	tree->left = malloc(sizeof(TreeNode));
	tree->right = malloc(sizeof(TreeNode));

	build_mt_subtree(tree->left, entries, start, start + k);
	build_mt_subtree(tree->right, entries, start + k, end);

	hash_internal(tree->data, tree->left->data, tree->right->data);
}

void build_mt_str(TreeNode *tree, const char *strings[], size_t length)
{
	Entry *entries;
	size_t i;
	entries = calloc(length, sizeof *entries);
	for (i = 0; i < length; ++i) {
		entries[i].data = (byte *)strings[i];
		entries[i].length = (size_t)strlen(strings[i]);
	}
	build_mt(tree, entries, length);
	free(entries);
}
#endif /* !WOLFSSL_MTC_EVALUATOR_ONLY */


MTC_EVALUATOR_SCOPE void hash_leaf(byte output[SHA256_DIGEST_SIZE],
	const Entry *entry)
{
	wc_Sha256 sha256;
	const byte prefix = 0x00;

	wc_InitSha256(&sha256);
	wc_Sha256Update(&sha256, &prefix, 1);
	wc_Sha256Update(&sha256, entry->data, entry->length);
	wc_Sha256Final(&sha256, output);
}

MTC_EVALUATOR_SCOPE void hash_internal(byte output[], const byte left[],
	const byte right[])
{
	wc_Sha256 sha256;
	const byte prefix = 0x01;
	wc_InitSha256(&sha256);
	wc_Sha256Update(&sha256, &prefix, 1);
	wc_Sha256Update(&sha256, left, SHA256_DIGEST_SIZE);
	wc_Sha256Update(&sha256, right, SHA256_DIGEST_SIZE);
	wc_Sha256Final(&sha256, output);
}

MTC_EVALUATOR_SCOPE int is_valid_subtree(word64 start, word64 end)
{
	word64 size;
	word64 alignment = 1;

	if (start >= end)
		return 0;
	if (start == 0)
		return 1;

	size = end - start;
	if (size > (W64LIT(1) << 63))
		return 0;
	while (alignment < size)
		alignment <<= 1;

	return (start & (alignment - 1)) == 0;
}

MTC_EVALUATOR_SCOPE int evaluate_inclusion_proof(word64 index, word64 start,
	word64 end, byte current_hash[], const byte *inclusion_proof,
	size_t inclusion_proof_length)
{
	byte result[SHA256_DIGEST_SIZE], next[SHA256_DIGEST_SIZE];
	const byte *proof_hash;
	word64 fn;
	word64 sn;
	size_t i;

	if (current_hash == NULL ||
			(inclusion_proof_length != 0 && inclusion_proof == NULL) ||
			!is_valid_subtree(start, end) || index < start || index >= end) {
		return -1;
	}

	fn = index - start;
	sn = end - start - 1;
	memcpy(result, current_hash, sizeof result);

	for (i = 0; i < inclusion_proof_length; ++i) {

		if (sn == 0) {
			return -1;
		}

		proof_hash = inclusion_proof + i * SHA256_DIGEST_SIZE;
		if ((fn & 1) != 0 || fn == sn) {
			hash_internal(next, proof_hash, result);

			while ((fn & 1) == 0) {
				fn >>= 1;
				sn >>= 1;
			}
		} else {
			hash_internal(next, result, proof_hash);
		}

		memcpy(result, next, sizeof result);
		fn >>= 1;
		sn >>= 1;
	}

	if (sn != 0) {
		return -1;
	}

	memcpy(current_hash, result, sizeof result);
	return 0;
}

#ifndef WOLFSSL_MTC_EVALUATOR_ONLY
void free_subtree(TreeNode *tree)
{
	if (tree == NULL) {
		return;
	}

	free_subtree(tree->left);
	free_subtree(tree->right);
	free(tree);
}

void free_tree_children(TreeNode *tree)
{
	if (tree == NULL) {
		return;
	}

	free_subtree(tree->left);
	free_subtree(tree->right);

	tree->left = NULL;
	tree->right = NULL;
}

void print_hash(const byte hash[SHA256_DIGEST_SIZE])
{
	size_t i;

	for (i = 0; i < 4; ++i) {
		printf("%02x", hash[i]);
	}

	printf("...");
}

void print_tree_recursive(const TreeNode *tree, const char *prefix, int is_last, const char *label)
{
	const char *extension;
	char *child_prefix;
	size_t prefix_length;

	if (tree == NULL) {
		return;
	}

	printf("%s%s%s: ", prefix, is_last ? "`-- " : "|-- ", label);

	print_hash(tree->data);
	printf("\n");

	if (tree->left == NULL && tree->right == NULL) {
		return;
	}

	extension = is_last ? "    " : "|   ";
	prefix_length = strlen(prefix);

	child_prefix = malloc(prefix_length + 5);
	if (child_prefix == NULL) {
		return;
	}

	memcpy(child_prefix, prefix, prefix_length);
	memcpy(child_prefix + prefix_length, extension, 5);

	if (tree->left != NULL && tree->right != NULL) {
		print_tree_recursive(
				tree->left,
				child_prefix,
				0,
				"L"
				);

		print_tree_recursive(
				tree->right,
				child_prefix,
				1,
				"R"
				);
	} else if (tree->left != NULL) {
		print_tree_recursive(
				tree->left,
				child_prefix,
				1,
				"L"
				);
	} else {
		print_tree_recursive(
				tree->right,
				child_prefix,
				1,
				"R"
				);
	}

	free(child_prefix);
}

void print_tree(const TreeNode *tree)
{
	if (tree == NULL) {
		puts("(empty tree)");
		return;
	}

	printf("root: ");
	print_hash(tree->data);
	printf("\n");

	if (tree->left != NULL && tree->right != NULL) {
		print_tree_recursive(tree->left, "", 0, "L");
		print_tree_recursive(tree->right, "", 1, "R");
	} else if (tree->left != NULL) {
		print_tree_recursive(tree->left, "", 1, "L");
	} else if (tree->right != NULL) {
		print_tree_recursive(tree->right, "", 1, "R");
	}
}
#endif /* !WOLFSSL_MTC_EVALUATOR_ONLY */

#undef MTC_EVALUATOR_SCOPE
