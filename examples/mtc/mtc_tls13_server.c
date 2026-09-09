/* Minimal TLS 1.3 server that selects an MTC certificate. */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif
#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif

#include <wolfssl/ssl.h>

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#if defined(WOLFSSL_MTC) && defined(WOLFSSL_TLS13) && \
    defined(HAVE_TLS_EXTENSIONS)

#ifdef WOLFSSL_CERT_SETUP_CB

#include "examples/mtc/trust_anchor_id.h"
#include "src/mtc/verify.h"

typedef struct MtcCertificateSelection {
    const char* standaloneCert;
    const char* landmarkCert;
    const char* privateKey;
    const char* selectedCert;
    byte caId[256];
    word16 caIdSz;
    byte landmarkId[256];
    word16 landmarkIdSz;
} MtcCertificateSelection;

static int TrustAnchorListContains(const byte* ids, word16 idsSz,
    const byte* encodedId, word16 encodedIdSz)
{
    word16 offset = 0;

    if (encodedIdSz < 2 || encodedId[0] != encodedIdSz - 1)
        return 0;

    while (offset < idsSz) {
        byte idSz = ids[offset++];

        if (idSz == 0 || idSz > idsSz - offset)
            return 0;
        if (idSz == encodedId[0] &&
                memcmp(ids + offset, encodedId + 1, idSz) == 0) {
            return 1;
        }
        offset = (word16)(offset + idSz);
    }

    return 0;
}

static int SelectMtcCertificate(WOLFSSL* ssl, void* arg)
{
    MtcCertificateSelection* selection = (MtcCertificateSelection*)arg;
    const byte* peerIds = NULL;
    word16 peerIdsSz = 0;
    const char* certificate = NULL;

    if (wolfSSL_GetPeerTrustAnchorIDs(ssl, &peerIds, &peerIdsSz) ==
            WOLFSSL_SUCCESS) {
        if (selection->landmarkCert != NULL &&
                TrustAnchorListContains(peerIds, peerIdsSz,
                    selection->landmarkId, selection->landmarkIdSz)) {
            certificate = selection->landmarkCert;
        }
        else if (TrustAnchorListContains(peerIds, peerIdsSz,
                selection->caId, selection->caIdSz)) {
            certificate = selection->standaloneCert;
        }
    }

    if (certificate == NULL) {
        fprintf(stderr, "client did not advertise a supported MTC trust "
            "anchor\n");
        return 0;
    }

    if (wolfSSL_use_certificate_file(ssl, certificate,
            WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS ||
            wolfSSL_use_PrivateKey_file(ssl, selection->privateKey,
                WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "failed to load selected certificate or private key\n");
        return 0;
    }

    selection->selectedCert = certificate;
    return 1;
}

#endif /* WOLFSSL_CERT_SETUP_CB */

int main(int argc, char** argv)
{
    struct sockaddr_in address;
    const char* standaloneCert;
    const char* privateKey;
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
#ifdef WOLFSSL_CERT_SETUP_CB
    WOLFSSL_X509* standaloneX509 = NULL;
    MtcCertificateSelection selection;
    size_t caIdSz = 0xffU;
#endif
    int listenFd = -1;
    int clientFd = -1;
    int reuse = 1;
    int ret = EXIT_FAILURE;

    if (argc != 3 && argc != 5) {
        fprintf(stderr, "usage: %s STANDALONE_CERTIFICATE_PEM "
            "PRIVATE_KEY_PEM [LANDMARK_CERTIFICATE_PEM "
            "LANDMARK_TRUST_ANCHOR_ID]\n", argv[0]);
        return EXIT_FAILURE;
    }

#ifndef WOLFSSL_CERT_SETUP_CB
    fprintf(stderr, "trust-anchor certificate selection requires wolfSSL to "
        "be configured with --enable-cert-setup-cb\n");
    return EXIT_FAILURE;
#endif

    standaloneCert = argv[1];
    privateKey = argv[2];

#ifdef WOLFSSL_CERT_SETUP_CB
    memset(&selection, 0, sizeof(selection));
    selection.standaloneCert = standaloneCert;
    selection.privateKey = privateKey;
    if (argc == 5) {
        selection.landmarkCert = argv[3];
        if (!MtcEncodeTrustAnchorID(argv[4], selection.landmarkId,
                &selection.landmarkIdSz)) {
            fprintf(stderr, "invalid landmark trust anchor ID: %s\n", argv[4]);
            return EXIT_FAILURE;
        }
    }
#endif

    wolfSSL_Init();
#ifdef WOLFSSL_CERT_SETUP_CB
    standaloneX509 = wolfSSL_X509_load_certificate_file(standaloneCert,
        WOLFSSL_FILETYPE_PEM);
    if (standaloneX509 == NULL || mtc_ca_id_from_issuer(standaloneX509,
            selection.caId + 1U, &caIdSz) != 0) {
        fprintf(stderr, "failed to extract the CA ID from the standalone "
            "certificate issuer\n");
        goto done;
    }
    selection.caId[0] = (byte)caIdSz;
    selection.caIdSz = (word16)(caIdSz + 1U);
#endif

    ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
    if (ctx == NULL ||
            wolfSSL_CTX_use_certificate_file(ctx, standaloneCert,
                WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS ||
            wolfSSL_CTX_use_PrivateKey_file(ctx, privateKey,
                WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "failed to load certificate or private key\n");
        goto done;
    }

#ifdef WOLFSSL_CERT_SETUP_CB
    wolfSSL_CTX_set_cert_cb(ctx, SelectMtcCertificate, &selection);
#endif

    listenFd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(11111);
    if (listenFd < 0) {
        perror("socket");
        goto done;
    }
    if (setsockopt(listenFd, SOL_SOCKET, SO_REUSEADDR, &reuse,
            sizeof(reuse)) < 0 ||
            bind(listenFd, (struct sockaddr*)&address, sizeof(address)) < 0 ||
            listen(listenFd, 1) < 0) {
        perror("listen");
        goto done;
    }

    printf("listening on 127.0.0.1:11111 \n");
    clientFd = accept(listenFd, NULL, NULL);
    ssl = wolfSSL_new(ctx);
    if (clientFd < 0 || ssl == NULL ||
            wolfSSL_set_fd(ssl, clientFd) != WOLFSSL_SUCCESS ||
            wolfSSL_accept(ssl) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "TLS handshake failed\n");
        goto done;
    }

#ifdef WOLFSSL_CERT_SETUP_CB
    printf("sent %s certificate: %s\n",
        selection.selectedCert == selection.landmarkCert ? "landmark" :
        "standalone", selection.selectedCert);
#else
    printf("sent standalone certificate: %s\n", standaloneCert);
#endif
    ret = EXIT_SUCCESS;

done:
#ifdef WOLFSSL_CERT_SETUP_CB
    wolfSSL_X509_free(standaloneX509);
#endif
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    if (clientFd >= 0)
        close(clientFd);
    if (listenFd >= 0)
        close(listenFd);
    wolfSSL_Cleanup();
    return ret;
}

#else

int main(void)
{
    fprintf(stderr, "configure wolfSSL with --enable-mtc\n");
    return EXIT_FAILURE;
}

#endif
