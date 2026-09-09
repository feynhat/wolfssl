# Minimal `trust_anchors` TLS extension

Enable this code with:

```sh
./configure --enable-mtc
```

MTC is disabled by default and requires TLS 1.3. CMake builds can use
`-DWOLFSSL_MTC=yes`. A custom `user_settings.h` build can define
`WOLFSSL_MTC` directly.

`trust_anchors.c` implements the native wolfSSL `TLSX_TRUST_ANCHORS`
extension. It is included by `src/tls.c`, alongside the other TLS extension
implementations, while keeping the implementation itself in `src/mtc`.
Its private storage type is declared in `trust_anchors.h` rather than in
`wolfssl/internal.h`.

Applications configure the ClientHello extension with:

```c
wolfSSL_UseTrustAnchorIDs(ssl, ids, idsSz);
```

`ids` is a `RequestedTrustAnchorList` without its two-byte vector length:

```text
1-byte ID length | opaque ID bytes | 1-byte ID length | opaque ID bytes | ...
```

After parsing a peer handshake message, applications can obtain the peer's
validated list with:

```c
const unsigned char* ids;
unsigned short idsSz;
wolfSSL_GetPeerTrustAnchorIDs(ssl, &ids, &idsSz);
```

The returned list uses the same one-byte-length-prefixed representation and is
owned by the `WOLFSSL` connection until it is replaced, the connection is
cleared, or the connection is freed. This allows a server certificate callback
to select a certificate after the ClientHello has been parsed.

The trust-anchor implementation only handles TLS extension storage,
validation, encoding, and parsing. It contains no Merkle-tree, subtree-hash,
inclusion-proof, or consistency-proof logic.

`mtc_cert.c` provides `mtc_cert_entry_from_tbs()`, an allocation-free
constructor for the draft-05 `tbs_cert_entry` wire encoding. It copies the
applicable DER fields from a `TBSCertificate`, replaces the complete
`subjectPublicKeyInfo` with its algorithm identifier and log-hash digest, and
prepends the entry extensions and type. The caller supplies the MTC CA's log
hash algorithm.

`cosign.c` provides `mtc_cosigned_message_create()`, an allocation-free
constructor for the draft-05 `CosignedMessage` wire encoding. It converts the
binary cosigner and log trust-anchor IDs to their `oid/1.3.6.1.4.1.*` ASCII
origins, validates the subtree interval and timestamp constraint, and writes
the fixed domain-separation label, integers, and subtree hash in TLS wire
format.

`verify.c` provides `mtc_ca_id_from_cert()` and
`mtc_ca_id_from_issuer()` to extract a binary CA `TrustAnchorID` from an MTC CA
certificate's subject or an MTC leaf certificate's issuer, respectively. It
also provides `mtc_verify_trusted_subtree()` for landmark-relative certificates
and `mtc_verify_cosignature()` for standalone certificates. Both reconstruct
the leaf entry and evaluate the SHA-256 inclusion proof with the verifier in
`mtc.c`. The trusted-subtree path checks the resulting hash and log number
against predistributed state. The standalone path constructs the
`CosignedMessage` and verifies the required CA cosignature using the algorithm
and public key from the CA certificate. These functions verify only the MTC
certificate-signature step; the caller remains responsible for the other PKIX
checks.
