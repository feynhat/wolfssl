#ifndef WOLFSSL_MTC_CERT_H
#define WOLFSSL_MTC_CERT_H

#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/hash.h>

/* Construct the TLS encoding of a tbs_cert_entry MerkleTreeCertEntry.
 *
 * tbs contains the complete DER encoding of a TBSCertificate, including its
 * SEQUENCE header. entryExtensions contains the contents of the
 * MerkleTreeCertEntryExtension vector, without the vector's two-byte length.
 * hashType is the issuing MTC CA's log hash algorithm.
 *
 * On input, *entryLen is the size of entry. On success it is set to the number
 * of bytes written. Passing entry as NULL sets *entryLen to the required size
 * and returns LENGTH_ONLY_E. A short output buffer returns BUFFER_E and also
 * reports the required size in *entryLen.
 */
int mtc_cert_entry_from_tbs(byte* entry, size_t* entryLen,
    const byte* tbs, size_t tbsLen, const byte* entryExtensions,
    size_t entryExtensionsLen, enum wc_HashType hashType);

#endif /* WOLFSSL_MTC_CERT_H */
