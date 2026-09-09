#include <stdio.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/openssl/bio.h>

#include "mtc_parse.h"

static int write_bytes(WOLFSSL_BIO *bio, const byte *bytes, size_t len);

int main(int argc, char **argv)
{
	WOLFSSL_X509* cert;
	WOLFSSL_BIO* bio;
	byte sig[10000], sn[100];
	int sigSz = sizeof(sig), snSz = sizeof(sn);
	word64 index = 0;
	MTCProof proof;
	int i;

	if (argc != 2) {
		fprintf(stderr, "usage: %s CERTIFICATE_PEM\n", argv[0]);
		return 1;
	}

	bio = wolfSSL_BIO_new_fp(stdout, WOLFSSL_BIO_NOCLOSE);
	if (bio == NULL) {
		fprintf(stderr, "failed to create output BIO\n");
		return 1;
	}

	cert = wolfSSL_X509_load_certificate_file(
		argv[1],
		WOLFSSL_FILETYPE_PEM
	);

	if (cert == NULL) {
		fprintf(stderr, "failed to load certificate\n");
		wolfSSL_BIO_free(bio);
		return 1;
	}

	if (wolfSSL_X509_get_signature(cert, sig, &sigSz) != SSL_SUCCESS) {
		fprintf(stderr, "failed to get signature\n");
		wolfSSL_X509_free(cert);
		wolfSSL_BIO_free(bio);
		return 1;
	}

	if (wolfSSL_X509_get_serial_number(cert, sn, &snSz) != SSL_SUCCESS) {
		fprintf(stderr, "failed to get serial number\n");
		wolfSSL_X509_free(cert);
		wolfSSL_BIO_free(bio);
		return 1;
	}

	for (i = snSz > 6 ? snSz - 6 : 0; i < snSz; ++i)
		index = (index << 8) | sn[i];

	if (wolfSSL_BIO_printf(bio, "signatureValue length = %d\n", sigSz) <= 0 ||
			wolfSSL_BIO_puts(bio, "\nSignature: ") <= 0 ||
			write_bytes(bio, sig, (size_t)sigSz) != 0) {
		fprintf(stderr, "failed to write certificate data to BIO\n");
		wolfSSL_X509_free(cert);
		wolfSSL_BIO_free(bio);
		return 1;
	}

	if (mtc_proof_parse(&proof, sig, (size_t)sigSz) != 0 ||
			mtc_proof_write_bio(bio, &proof, index, 0) != 0) {
		fprintf(stderr, "failed to parse or write MTC proof\n");
		wolfSSL_X509_free(cert);
		wolfSSL_BIO_free(bio);
		return 1;
	}

	wolfSSL_X509_free(cert);
	wolfSSL_BIO_free(bio);

	return 0;
}

static int write_bytes(WOLFSSL_BIO *bio, const byte *bytes, size_t len)
{
	size_t i;

	for (i = 0; i < len; ++i) {
		if (wolfSSL_BIO_printf(bio, "%02X", bytes[i]) <= 0)
			return -1;
	}

	return wolfSSL_BIO_puts(bio, "\n") <= 0 ? -1 : 0;
}
