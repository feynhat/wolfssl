# Merkle Tree Certificate examples

These examples target the experimental OIDs and wire formats in
`draft-ietf-plants-merkle-tree-certs-05`.

Configure wolfSSL with `--enable-mtc` before building the TLS examples. Enable
the signature algorithm used by the MTC CA as well; the demo certificate set
currently uses ML-DSA-44:

```sh
./configure --enable-mtc --enable-mldsa --enable-cert-setup-cb \
    --enable-opensslextra
make
```

`--enable-cert-setup-cb` is required for the example server's trust-anchor
certificate selection, including the standalone CA-ID check. A build with
`--enable-opensslextra` also enables this callback.

The equivalent CMake options are:

```sh
cmake -S . -B build \
    -DWOLFSSL_MTC=yes -DWOLFSSL_MLDSA=yes \
    -DWOLFSSL_CERT_SETUP_CB=yes -DWOLFSSL_OPENSSLEXTRA=yes \
    -DWOLFSSL_EXAMPLES=yes
cmake --build build
```

## TLS 1.3 client

`mtc_tls13_client.c` is a minimal TLS 1.3 client that sends MTC trust anchor IDs
in its ClientHello and verifies the standalone or landmark-relative certificate
returned by the server. It takes the MTC CA certificate and an optional latest
trusted landmark, then connects to `127.0.0.1:11111`. The client extracts the CA
ID from the certificate's subject.

```sh
./examples/mtc/mtc_tls13_client ca-cert.pem
./examples/mtc/mtc_tls13_client \
    --landmark 1.1 --hash "BASE64_SUBTREE_HASH" ca-cert.pem
```

The draft-05 test encoding carries the dotted-decimal CA ID in the CA
certificate's subject. The client converts it to the binary ASN.1
`RELATIVE-OID` representation and adds the one-byte ID length required by
`wolfSSL_UseTrustAnchorIDs()`; wolfSSL adds the two-byte list length used on the
wire. After the TLS handshake, the client retrieves the peer `WOLFSSL_X509` and
prints it with `wolfSSL_X509_print_fp()`, then verifies it with the supplied CA
certificate. The X.509 text printer requires `--enable-opensslextra`. Both
verification paths parse the `MTCProof`, reconstruct the log entry, and evaluate
the inclusion proof. The standalone path calls `mtc_verify_cosignature()` to
verify the CA cosignature.

`--landmark LOG.LANDMARK` identifies the latest trusted landmark for a log and
requires `--hash BASE64`. The hash must decode to a 32-byte SHA-256 landmark
subtree hash. The client constructs the draft's single-log landmark-group ID
`{CA-ID}.2.LOG.LANDMARK` and adds it alongside the CA ID in the
`trust_anchors` extension. For example, `--landmark 1.1` with CA ID `32473.1`
adds `32473.1.2.1.1`. The hash is local relying-party state and is not sent in
the TLS extension. For a landmark-relative certificate, the client reconstructs
the log entry, evaluates the inclusion proof, checks that the certificate uses
the requested log, and compares the result with this trusted hash. If the
server instead returns its standalone fallback, the client verifies the CA
cosignature.

The IETF draft has not assigned an ExtensionType value yet. This example and
wolfSSL therefore default `WOLFSSL_TRUST_ANCHORS_EXT_TYPE` to the private-use
value `0xffa6`. The server must use the same value. An experiment can override
it at compile time, but the same definition must be used when compiling both
wolfSSL and the client.

The generic TLS path verifier is disabled because it does not yet dispatch
`id-alg-mtcProof` certificates to the MTC verifier. The explicit call verifies
the MTC replacement for the certificate-signature step. This minimal example
still does not check the hostname, certificate chain, validity period, or other
PKIX requirements and must not be used as a complete server authenticator.

## TLS 1.3 server

`mtc_tls13_server.c` is a one-connection test server. Give it a standalone MTC
certificate and its matching private key:

```sh
./examples/mtc/mtc_tls13_server standalone-cert.pem private-key.pem
```

To test certificate selection, additionally give it a landmark-relative
variant of the same leaf and the exact trust anchor ID which signals that the
client trusts the landmark:

```sh
./examples/mtc/mtc_tls13_server \
    standalone-cert.pem private-key.pem \
    landmark-cert.pem landmark-trust-anchor-id
```

The standalone and landmark certificates must be variants of the same log
entry and therefore use the same private key. After parsing ClientHello, the
server's certificate setup callback checks the client's length-prefixed
`TrustAnchorID` list. It prefers the landmark certificate when that certificate
was configured and its exact trust anchor ID is present. Otherwise, it selects
the standalone certificate only when the CA ID extracted from the standalone
certificate's issuer is present. If neither condition is met, certificate setup
fails and the handshake is rejected. The comparisons are exact ID comparisons;
the example does not maintain a general trust-anchor group database.

For example, `cert_10_0.pem` is the standalone variant for entry 10 and
`cert_10_12.pem` is its landmark-1 variant. The draft's single-log landmark
group for CA `32473.1`, log 1, landmark 1 is `32473.1.2.1.1`:

```sh
./examples/mtc/mtc_tls13_server \
    ../merkle-tree-certs/demo/sk-out/cert_10_0.pem \
    ../merkle-tree-certs/demo/sk-out/entry_10_key.pem \
    ../merkle-tree-certs/demo/sk-out/cert_10_12.pem \
    32473.1.2.1.1
```

Then run the client in another terminal:

```sh
./examples/mtc/mtc_tls13_client ca-cert.pem
./examples/mtc/mtc_tls13_client \
    --landmark 1.1 --hash "BASE64_SUBTREE_HASH" ca-cert.pem
```

The extracted CA ID selects the standalone fallback. Passing `--landmark 1.1`
with its `--hash` advertises the configured `32473.1.2.1.1` landmark group and
causes the example server to select and the client to verify the
landmark-relative certificate. The server prints which certificate it selected
and exits after the one connection.

## Inclusion-proof inspector

`mtc_inclusion_proof.c` extracts the proof from an MTC certificate and
reconstructs its Merkle leaf hash. Run it with `--help`-style usage shown when
no certificate is supplied.
