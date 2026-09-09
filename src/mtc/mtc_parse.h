#ifndef WOLFSSL_MTC_PARSE_H
#define WOLFSSL_MTC_PARSE_H

#include <wolfssl/wolfcrypt/types.h>

#if defined(OPENSSL_EXTRA) && !defined(NO_BIO)
    #include <wolfssl/openssl/compat_types.h>
#endif

typedef struct {
    const byte *extensions;
    word16 extensions_len;

    word64 start;   /* only lower 48 bits used */
    word64 end;     /* only lower 48 bits used */

    const byte *inclusion_proof;
    word16 inclusion_proof_len;

    const byte *signatures;
    word16 signatures_len;
} MTCProof;

int mtc_proof_parse(MTCProof *proof, const byte *buf, size_t len);

#if defined(OPENSSL_EXTRA) && !defined(NO_BIO)
int mtc_proof_write_bio(WOLFSSL_BIO *bio, const MTCProof *proof,
    word64 index, int indent);
#endif

#endif /* WOLFSSL_MTC_PARSE_H */
