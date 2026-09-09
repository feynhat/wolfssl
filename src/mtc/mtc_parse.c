#include <wolfssl/wolfcrypt/libwolfssl_sources.h>
#include <wolfssl/wolfcrypt/types.h>
#if defined(OPENSSL_EXTRA) && !defined(NO_BIO)
    #include <wolfssl/ssl.h>
    #include <wolfssl/wolfcrypt/sha256.h>
#endif

#include "mtc_parse.h"

static word16 read_u16(const byte *p)
{
    return ((word16)p[0] << 8) |
            (word16)p[1];
}

static word64 read_u48(const byte *p)
{
    word64 x = 0;
    size_t i;

    for (i = 0; i < 6; ++i)
        x = (x << 8) | p[i];

    return x;
}

int mtc_proof_parse(MTCProof *proof, const byte *buf, size_t len)
{
    size_t off = 0;
    word16 n;

    if (proof == NULL || buf == NULL)
        return -1;

    /*
     * extensions<0..2^16-1>
     *
     * 2-byte length + contents
     */
    if (len - off < 2)
        return -1;

    n = read_u16(buf + off);
    off += 2;

    if (len - off < n)
        return -1;

    proof->extensions = buf + off;
    proof->extensions_len = n;
    off += n;


    /*
     * uint48 start
     */
    if (len - off < 6)
        return -1;

    proof->start = read_u48(buf + off);
    off += 6;


    /*
     * uint48 end
     */
    if (len - off < 6)
        return -1;

    proof->end = read_u48(buf + off);
    off += 6;


    /*
     * HashValue inclusion_proof<0..2^16-1>
     *
     * 2-byte byte-length + hashes
     */
    if (len - off < 2)
        return -1;

    n = read_u16(buf + off);
    off += 2;

    if (len - off < n)
        return -1;

    proof->inclusion_proof = buf + off;
    proof->inclusion_proof_len = n;
    off += n;


    /*
     * MTCSignature signatures<0..2^16-1>
     *
     * 2-byte byte-length + signatures
     */
    if (len - off < 2)
        return -1;

    n = read_u16(buf + off);
    off += 2;

    if (len - off < n)
        return -1;

    proof->signatures = buf + off;
    proof->signatures_len = n;
    off += n;


    /* There should be nothing left over. */
    if (off != len)
        return -1;

    return 0;
}

#if defined(OPENSSL_EXTRA) && !defined(NO_BIO)

static int mtc_bio_write_all(WOLFSSL_BIO *bio, const void *data, size_t len)
{
    const byte *p = (const byte *)data;

    while (len > 0) {
        int chunk = len > (size_t)0x7fffffff ? 0x7fffffff : (int)len;
        int written = wolfSSL_BIO_write(bio, p, chunk);

        if (written <= 0 || written > chunk)
            return -1;

        p += written;
        len -= (size_t)written;
    }

    return 0;
}

static int mtc_bio_write_indent(WOLFSSL_BIO *bio, int indent)
{
    static const char spaces[] =
        "                                                                ";

    while (indent > 0) {
        int chunk = indent;

        if (chunk > (int)(sizeof(spaces) - 1))
            chunk = (int)(sizeof(spaces) - 1);
        if (mtc_bio_write_all(bio, spaces, (size_t)chunk) != 0)
            return -1;
        indent -= chunk;
    }

    return 0;
}

static int mtc_bio_write_colon_hex(WOLFSSL_BIO *bio, const byte *bytes,
    size_t len)
{
    static const char hex[] = "0123456789ABCDEF";
    char out[WC_SHA256_DIGEST_SIZE * 3];
    size_t i;
    size_t outSz = 0;

    if (len > WC_SHA256_DIGEST_SIZE)
        return -1;

    for (i = 0; i < len; ++i) {
        if (i > 0)
            out[outSz++] = ':';
        out[outSz++] = hex[bytes[i] >> 4];
        out[outSz++] = hex[bytes[i] & 0x0f];
    }

    return mtc_bio_write_all(bio, out, outSz);
}

/* Match the number of octets per line used by X509PrintSignature_ex(). */
static int mtc_bio_write_hex_lines(WOLFSSL_BIO *bio, int indent,
    const byte *bytes, size_t bytesSz)
{
    enum { MTC_BIO_BYTES_PER_LINE = 18 };

    while (bytesSz > 0U) {
        size_t lineSz = bytesSz;

        if (lineSz > MTC_BIO_BYTES_PER_LINE)
            lineSz = MTC_BIO_BYTES_PER_LINE;
        if (mtc_bio_write_indent(bio, indent) != 0 ||
                mtc_bio_write_colon_hex(bio, bytes, lineSz) != 0 ||
                (bytesSz > lineSz &&
                    mtc_bio_write_all(bio, ":", 1) != 0) ||
                mtc_bio_write_all(bio, "\n", 1) != 0) {
            return -1;
        }

        bytes += lineSz;
        bytesSz -= lineSz;
    }

    return 0;
}

static int mtc_bio_write_u64(WOLFSSL_BIO *bio, word64 value)
{
    char number[20];
    size_t pos = sizeof(number);

    do {
        number[--pos] = (char)('0' + value % 10);
        value /= 10;
    } while (value != 0);

    return mtc_bio_write_all(bio, number + pos, sizeof(number) - pos);
}

static int mtc_bio_write_bytes_line(WOLFSSL_BIO *bio, int indent,
    const char *label, size_t labelSz, const byte *bytes, size_t bytesSz)
{
    if (mtc_bio_write_indent(bio, indent) != 0 ||
            mtc_bio_write_all(bio, label, labelSz) != 0 ||
            mtc_bio_write_all(bio, "\n", 1) != 0) {
        return -1;
    }

    return mtc_bio_write_hex_lines(bio, indent + 4, bytes, bytesSz);
}

static int mtc_bio_write_inclusion_proof(WOLFSSL_BIO *bio, int indent,
    const byte *proof, size_t proofSz)
{
    static const char label[] = "Inclusion Proof:\n";

    if (mtc_bio_write_indent(bio, indent) != 0 ||
            mtc_bio_write_all(bio, label, sizeof(label) - 1) != 0) {
        return -1;
    }

    while (proofSz > 0) {
        size_t hashSz = proofSz;

        if (hashSz > WC_SHA256_DIGEST_SIZE)
            hashSz = WC_SHA256_DIGEST_SIZE;

        if (mtc_bio_write_hex_lines(bio, indent + 4, proof, hashSz) != 0) {
            return -1;
        }

        proof += hashSz;
        proofSz -= hashSz;
    }

    return 0;
}

int mtc_proof_write_bio(WOLFSSL_BIO *bio, const MTCProof *proof,
    word64 index, int indent)
{
    static const char extensionsLabel[] = "Extensions:";
    static const char startLabel[] = "Start: ";
    static const char endLabel[] = "    End: ";
    static const char indexLabel[] = "Index: ";
    static const char signaturesLabel[] = "Signatures:";

    if (bio == NULL || proof == NULL || indent < 0 ||
            (proof->extensions == NULL && proof->extensions_len != 0) ||
            (proof->inclusion_proof == NULL &&
                proof->inclusion_proof_len != 0) ||
            (proof->signatures == NULL && proof->signatures_len != 0)) {
        return -1;
    }

    if (mtc_bio_write_bytes_line(bio, indent, extensionsLabel,
            sizeof(extensionsLabel) - 1, proof->extensions,
            proof->extensions_len) != 0) {
        return -1;
    }

    if (mtc_bio_write_indent(bio, indent) != 0 ||
            mtc_bio_write_all(bio, startLabel, sizeof(startLabel) - 1) != 0 ||
            mtc_bio_write_u64(bio, proof->start) != 0 ||
            mtc_bio_write_all(bio, endLabel, sizeof(endLabel) - 1) != 0 ||
            mtc_bio_write_u64(bio, proof->end) != 0 ||
            mtc_bio_write_all(bio, "\n", 1) != 0) {
        return -1;
    }

    if (mtc_bio_write_indent(bio, indent) != 0 ||
            mtc_bio_write_all(bio, indexLabel, sizeof(indexLabel) - 1) != 0 ||
            mtc_bio_write_u64(bio, index) != 0 ||
            mtc_bio_write_all(bio, "\n", 1) != 0) {
        return -1;
    }

    if (mtc_bio_write_inclusion_proof(bio, indent,
            proof->inclusion_proof, proof->inclusion_proof_len) != 0) {
        return -1;
    }

    return mtc_bio_write_bytes_line(bio, indent, signaturesLabel,
        sizeof(signaturesLabel) - 1, proof->signatures,
        proof->signatures_len);
}

#endif /* OPENSSL_EXTRA && !NO_BIO */
