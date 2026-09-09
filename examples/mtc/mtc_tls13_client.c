/* Minimal TLS 1.3 client that verifies an MTC certificate. */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif
#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif

#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/sha256.h>

#include "src/mtc/verify.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#if defined(WOLFSSL_MTC) && defined(WOLFSSL_TLS13) && \
    defined(HAVE_TLS_EXTENSIONS) && defined(KEEP_PEER_CERT)

static void Usage(const char* program)
{
    fprintf(stderr, "usage: %s [--landmark LOG.LANDMARK --hash BASE64] "
        "MTC_CA_CERTIFICATE_PEM\n", program);
}

static int ParseArguments(int argc, char** argv, const char** caCert,
    const char** landmark, const char** hash)
{
    int i;

    *caCert = NULL;
    *landmark = NULL;
    *hash = NULL;
    for (i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--landmark") == 0) {
            if (*landmark != NULL || ++i == argc)
                return 0;
            *landmark = argv[i];
        }
        else if (strncmp(argv[i], "--landmark=", 11) == 0) {
            if (*landmark != NULL || argv[i][11] == '\0')
                return 0;
            *landmark = argv[i] + 11;
        }
        else if (strcmp(argv[i], "--hash") == 0) {
            if (*hash != NULL || ++i == argc)
                return 0;
            *hash = argv[i];
        }
        else if (strncmp(argv[i], "--hash=", 7) == 0) {
            if (*hash != NULL || argv[i][7] == '\0')
                return 0;
            *hash = argv[i] + 7;
        }
        else if (argv[i][0] == '-' || *caCert != NULL) {
            return 0;
        }
        else {
            *caCert = argv[i];
        }
    }

    return *caCert != NULL;
}

static int DecodeLandmarkHash(const char* encoded,
    byte hash[WC_SHA256_DIGEST_SIZE])
{
    size_t encodedSz;
    word32 hashSz = WC_SHA256_DIGEST_SIZE;

    if (encoded == NULL)
        return 0;
    encodedSz = strlen(encoded);
    if (encodedSz == 0U || encodedSz > 0xffffffffU ||
            Base64_Decode((const byte*)encoded, (word32)encodedSz, hash,
                &hashSz) != 0 || hashSz != WC_SHA256_DIGEST_SIZE) {
        return 0;
    }

    return 1;
}

static int ParseLogLandmark(const char* value, word16* logNumber,
    word64* landmarkNumber)
{
    const char* dot;
    const char* current;
    word64 log = 0;
    word64 landmark = 0;

    if (value == NULL || logNumber == NULL || landmarkNumber == NULL)
        return 0;

    dot = strchr(value, '.');
    if (dot == NULL || dot == value || dot[1] == '\0' ||
            strchr(dot + 1, '.') != NULL) {
        return 0;
    }
    for (current = value; current < dot; ++current) {
        word64 digit;

        if (*current < '0' || *current > '9')
            return 0;
        digit = (word64)(*current - '0');
        if (log > (W64LIT(0xffff) - digit) / 10U)
            return 0;
        log = log * 10U + digit;
    }
    for (current = dot + 1; *current != '\0'; ++current) {
        word64 digit;

        if (*current < '0' || *current > '9')
            return 0;
        digit = (word64)(*current - '0');
        if (landmark > (W64LIT(0x0000ffffffffffff) - digit) / 10U)
            return 0;
        landmark = landmark * 10U + digit;
    }
    if (log == 0U || landmark == 0U)
        return 0;

    *logNumber = (word16)log;
    *landmarkNumber = landmark;
    return 1;
}

static int AppendIdComponent(byte* id, size_t capacity, size_t* idSz,
    word64 value)
{
    byte encoded[10];
    size_t encodedSz = 0;
    size_t i;

    do {
        encoded[encodedSz++] = (byte)(value & 0x7fU);
        value >>= 7;
    } while (value != 0U);
    if (*idSz > capacity || encodedSz > capacity - *idSz)
        return 0;

    for (i = encodedSz; i > 0U; --i) {
        byte next = encoded[i - 1U];

        if (i != 1U)
            next |= 0x80U;
        id[(*idSz)++] = next;
    }
    return 1;
}

static int AddLandmarkGroupId(byte* ids, size_t capacity, word16* idsSz,
    const byte* caId, size_t caIdSz, word16 logNumber,
    word64 landmarkNumber)
{
    size_t offset = *idsSz;
    size_t idSz = 0;
    byte* id;

    if (offset >= capacity || caIdSz == 0U || caIdSz > 0xffU)
        return 0;

    id = ids + offset + 1U;
    if (caIdSz > capacity - offset - 1U)
        return 0;
    memcpy(id, caId, caIdSz);
    idSz = caIdSz;

    /* A single-log landmark group is { CA-ID, 2, log, landmark }. */
    if (!AppendIdComponent(id, capacity - offset - 1U, &idSz, 2U) ||
            !AppendIdComponent(id, capacity - offset - 1U, &idSz,
                logNumber) ||
            !AppendIdComponent(id, capacity - offset - 1U, &idSz,
                landmarkNumber) || idSz > 0xffU) {
        return 0;
    }

    ids[offset] = (byte)idSz;
    *idsSz = (word16)(offset + 1U + idSz);
    return 1;
}

static int PrintPeerCertificate(WOLFSSL_X509* peer)
{
#if defined(OPENSSL_EXTRA) && defined(XSNPRINTF) && \
    !defined(NO_BIO) && !defined(NO_FILESYSTEM)
    printf("received server certificate:\n");
    if (wolfSSL_X509_print_fp(stdout, peer) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "failed to print received server certificate\n");
        return 0;
    }
    return 1;
#else
    (void)peer;
    fprintf(stderr, "printing the received certificate requires "
        "--enable-opensslextra, BIO, and filesystem support\n");
    return 0;
#endif
}

int main(int argc, char** argv)
{
    struct sockaddr_in server;
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    WOLFSSL_X509* ca = NULL;
    WOLFSSL_X509* peer = NULL;
    byte ids[512];
    byte landmarkHash[WC_SHA256_DIGEST_SIZE];
    size_t caIdSz = 0xffU;
    word16 idsSz;
    word16 logNumber = 0;
    word64 landmarkNumber = 0;
    const char* caCert = NULL;
    const char* landmark = NULL;
    const char* hash = NULL;
    int fd = -1;
    int landmarkVerifyRet = 0;
    int verifiedLandmark = 0;
    int verifyRet;
    int ret = EXIT_FAILURE;

    if (!ParseArguments(argc, argv, &caCert, &landmark, &hash)) {
        Usage(argv[0]);
        return EXIT_FAILURE;
    }
    if (landmark != NULL && hash == NULL) {
        fprintf(stderr, "--landmark requires --hash\n");
        Usage(argv[0]);
        return EXIT_FAILURE;
    }
    if (hash != NULL && landmark == NULL) {
        fprintf(stderr, "--hash requires --landmark\n");
        Usage(argv[0]);
        return EXIT_FAILURE;
    }
    if (landmark != NULL && !ParseLogLandmark(landmark, &logNumber,
            &landmarkNumber)) {
        fprintf(stderr, "invalid --landmark value: %s "
            "(expected LOG.LANDMARK)\n", landmark);
        return EXIT_FAILURE;
    }
    if (hash != NULL && !DecodeLandmarkHash(hash, landmarkHash)) {
        fprintf(stderr, "invalid --hash value: expected a Base64-encoded "
            "SHA-256 subtree hash\n");
        return EXIT_FAILURE;
    }

    wolfSSL_Init();
    ca = wolfSSL_X509_load_certificate_file(caCert, WOLFSSL_FILETYPE_PEM);
    if (ca == NULL) {
        fprintf(stderr, "failed to load MTC CA certificate: %s\n", caCert);
        goto done;
    }
    verifyRet = mtc_ca_id_from_cert(ca, ids + 1U, &caIdSz);
    if (verifyRet != 0) {
        fprintf(stderr, "failed to extract CA ID from MTC CA certificate: "
            "%d\n", verifyRet);
        goto done;
    }
    ids[0] = (byte)caIdSz;
    idsSz = (word16)(caIdSz + 1U);
    if (landmark != NULL && !AddLandmarkGroupId(ids, sizeof(ids), &idsSz,
            ids + 1U, caIdSz, logNumber, landmarkNumber)) {
        fprintf(stderr, "failed to construct landmark-group trust anchor "
            "ID\n");
        goto done;
    }

    ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (ctx == NULL)
        goto done;

    /* The generic path verifier does not yet dispatch id-alg-mtcProof to the
     * MTC verifier. Retain the peer certificate and verify its MTC signature
     * explicitly after CertificateVerify completes. */
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, NULL);
    ssl = wolfSSL_new(ctx);
    if (ssl == NULL ||
            wolfSSL_UseTrustAnchorIDs(ssl, ids, idsSz) != WOLFSSL_SUCCESS) {
        goto done;
    }

    fd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(11111);
    inet_pton(AF_INET, "127.0.0.1", &server.sin_addr);
    if (fd < 0 || connect(fd, (struct sockaddr*)&server, sizeof(server)) < 0 ||
            wolfSSL_set_fd(ssl, fd) != WOLFSSL_SUCCESS ||
            wolfSSL_connect(ssl) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "TLS handshake failed\n");
        goto done;
    }

    peer = wolfSSL_get_peer_certificate(ssl);
    if (peer == NULL) {
        fprintf(stderr, "server did not send a certificate\n");
        goto done;
    }
    if (!PrintPeerCertificate(peer))
        goto done;

    if (landmark != NULL) {
        landmarkVerifyRet = mtc_verify_trusted_subtree(peer, ca, logNumber,
            landmarkHash, sizeof(landmarkHash));
        if (landmarkVerifyRet == 0) {
            verifiedLandmark = 1;
            verifyRet = 0;
        }
        else {
            /* The server may not have the advertised landmark certificate and
             * may have selected the standalone fallback. */
            verifyRet = mtc_verify_cosignature(peer, ca);
            if (verifyRet != 0) {
                fprintf(stderr, "MTC certificate failed trusted landmark "
                    "verification (%d) and standalone verification (%d)\n",
                    landmarkVerifyRet, verifyRet);
                goto done;
            }
        }
    }
    else {
        verifyRet = mtc_verify_cosignature(peer, ca);
        if (verifyRet != 0) {
            fprintf(stderr, "standalone MTC certificate verification failed: "
                "%d\n", verifyRet);
            goto done;
        }
    }

    printf("sent the CA ID extracted from: %s\n", caCert);
    if (landmark != NULL)
        printf("sent landmark group for log.landmark %s with a trusted "
            "subtree hash\n", landmark);
    printf("verified %s certificate from MTC CA: %s\n",
        verifiedLandmark ? "landmark-relative" : "standalone", caCert);
    ret = EXIT_SUCCESS;

done:
    wolfSSL_X509_free(peer);
    wolfSSL_X509_free(ca);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    if (fd >= 0)
        close(fd);
    wolfSSL_Cleanup();
    return ret;
}

#else

int main(void)
{
    fprintf(stderr, "configure wolfSSL with --enable-mtc and peer certificate "
        "retention\n");
    return EXIT_FAILURE;
}

#endif
