/* verify.h
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 */

#ifndef WOLFSSL_MTC_VERIFY_H
#define WOLFSSL_MTC_VERIFY_H

#include <wolfssl/ssl.h>

#ifdef WOLFSSL_MTC
/* Extract the binary TrustAnchorID from the subject of an MTC CA
 * certificate. idLen supplies the size of id on input and receives the
 * extracted ID size on success.
 *
 * Returns 0 on success or a negative wolfSSL error code on failure.
 */
WOLFSSL_API int mtc_ca_id_from_cert(const WOLFSSL_X509* ca, byte* id,
    size_t* idLen);

/* Extract the binary CA TrustAnchorID from the issuer of an MTC leaf
 * certificate. idLen supplies the size of id on input and receives the
 * extracted ID size on success.
 *
 * Returns 0 on success or a negative wolfSSL error code on failure.
 */
WOLFSSL_API int mtc_ca_id_from_issuer(const WOLFSSL_X509* cert, byte* id,
    size_t* idLen);

/* Verify a draft-05 MTC certificate against a predistributed trusted subtree.
 * The certificate's serial number must identify logNumber, and evaluation of
 * its inclusion proof must produce trustedSubtreeHash. The caller is
 * responsible for binding the hash to the advertised landmark and for all
 * other PKIX validation checks.
 *
 * Returns 0 on success or a negative wolfSSL error code on failure.
 */
WOLFSSL_API int mtc_verify_trusted_subtree(const WOLFSSL_X509* cert,
    const WOLFSSL_X509* issuer, word32 logNumber,
    const byte* trustedSubtreeHash, size_t trustedSubtreeHashLen);

/* Verify the CA cosignature in a draft-05 standalone Merkle Tree
 * Certificate.
 *
 * cert is the standalone leaf certificate and issuer is its MTC CA
 * certificate. The issuer certificate supplies the CA/cosigner ID, log hash,
 * cosignature algorithm, serial-number range, and public key. Additional
 * cosignatures in the proof are validated structurally but otherwise ignored.
 *
 * This verifies the MTC replacement for the certificate-signature step only;
 * callers must still perform the remaining PKIX validation checks.
 *
 * Returns 0 on success or a negative wolfSSL error code on failure.
 */
WOLFSSL_API int mtc_verify_cosignature(const WOLFSSL_X509* cert,
    const WOLFSSL_X509* issuer);
#endif /* WOLFSSL_MTC */

#endif /* WOLFSSL_MTC_VERIFY_H */
