#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/types.h>

#include "mtc_cert.h"

#ifndef NO_HASH_WRAPPER

enum {
    MTC_DER_INTEGER          = 0x02,
    MTC_DER_BIT_STRING       = 0x03,
    MTC_DER_OCTET_STRING     = 0x04,
    MTC_DER_SEQUENCE         = 0x30,
    MTC_DER_ISSUER_UID       = 0x81,
    MTC_DER_SUBJECT_UID      = 0x82,
    MTC_DER_EXPLICIT_VERSION = 0xa0,
    MTC_DER_EXTENSIONS       = 0xa3,

    MTC_TBS_CERT_ENTRY       = 1
};

typedef struct MtcCertSpan {
    const byte* data;
    size_t len;
} MtcCertSpan;

typedef struct MtcCertCursor {
    const byte* data;
    size_t len;
    size_t offset;
} MtcCertCursor;

typedef struct MtcTbsFields {
    MtcCertSpan version;
    MtcCertSpan issuer;
    MtcCertSpan validity;
    MtcCertSpan subject;
    MtcCertSpan publicKeyAlgorithm;
    MtcCertSpan subjectPublicKeyInfo;
    MtcCertSpan fieldsAfterSubjectPublicKeyInfo;
} MtcTbsFields;

/* Read one DER TLV and retain views of both its complete encoding and its
 * contents. All TBSCertificate fields used here have low-tag-number tags. */
static int mtc_cert_read_der(MtcCertCursor* cursor, byte expectedTag,
    MtcCertSpan* encoded, MtcCertSpan* contents)
{
    size_t start;
    size_t len;
    byte tag;
    byte lengthByte;

    if (cursor->offset > cursor->len ||
            cursor->len - cursor->offset < 2U) {
        return BUFFER_E;
    }

    start = cursor->offset;
    tag = cursor->data[cursor->offset++];
    if ((tag & 0x1fU) == 0x1fU || tag != expectedTag)
        return ASN_PARSE_E;

    lengthByte = cursor->data[cursor->offset++];
    if ((lengthByte & 0x80U) == 0U) {
        len = lengthByte;
    }
    else {
        size_t lengthBytes = lengthByte & 0x7fU;
        size_t i;

        /* DER does not permit indefinite or non-minimal lengths. */
        if (lengthBytes == 0U || lengthBytes > sizeof(size_t))
            return ASN_PARSE_E;
        if (lengthBytes > cursor->len - cursor->offset)
            return BUFFER_E;
        if (cursor->data[cursor->offset] == 0U)
            return ASN_PARSE_E;

        len = 0;
        for (i = 0; i < lengthBytes; ++i) {
            byte value = cursor->data[cursor->offset++];

            if (len > ((size_t)-1 - value) / 256U)
                return ASN_PARSE_E;
            len = len * 256U + value;
        }
        if (len < 128U)
            return ASN_PARSE_E;
    }

    if (len > cursor->len - cursor->offset)
        return BUFFER_E;

    if (contents != NULL) {
        contents->data = cursor->data + cursor->offset;
        contents->len = len;
    }
    cursor->offset += len;
    if (encoded != NULL) {
        encoded->data = cursor->data + start;
        encoded->len = cursor->offset - start;
    }

    return 0;
}

static int mtc_cert_validate_integer(const MtcCertSpan* integer)
{
    if (integer->len == 0U)
        return ASN_PARSE_E;

    /* X.690 11.1: the two's-complement encoding must be minimal. */
    if (integer->len > 1U &&
            ((integer->data[0] == 0x00 &&
              (integer->data[1] & 0x80U) == 0U) ||
             (integer->data[0] == 0xff &&
              (integer->data[1] & 0x80U) != 0U))) {
        return ASN_PARSE_E;
    }

    return 0;
}

/* UniqueIdentifier is an IMPLICIT BIT STRING, so its contents begin with the
 * unused-bit count even though the context-specific tag replaces 0x03. */
static int mtc_cert_validate_bit_string(const MtcCertSpan* bitString)
{
    byte unused;

    if (bitString->len == 0U)
        return ASN_PARSE_E;
    unused = bitString->data[0];
    if (unused > 7U || (bitString->len == 1U && unused != 0U))
        return ASN_PARSE_E;
    if (unused != 0U &&
            (bitString->data[bitString->len - 1U] &
             (byte)((1U << unused) - 1U)) != 0U) {
        return ASN_PARSE_E;
    }

    return 0;
}

static int mtc_cert_validate_tbs_tail(const MtcCertSpan* tail)
{
    MtcCertCursor cursor;
    MtcCertSpan contents;
    int ret = 0;

    cursor.data = tail->data;
    cursor.len = tail->len;
    cursor.offset = 0;

    if (cursor.offset < cursor.len &&
            cursor.data[cursor.offset] == MTC_DER_ISSUER_UID) {
        ret = mtc_cert_read_der(&cursor, MTC_DER_ISSUER_UID, NULL,
            &contents);
        if (ret == 0)
            ret = mtc_cert_validate_bit_string(&contents);
    }
    if (ret == 0 && cursor.offset < cursor.len &&
            cursor.data[cursor.offset] == MTC_DER_SUBJECT_UID) {
        ret = mtc_cert_read_der(&cursor, MTC_DER_SUBJECT_UID, NULL,
            &contents);
        if (ret == 0)
            ret = mtc_cert_validate_bit_string(&contents);
    }
    if (ret == 0 && cursor.offset < cursor.len &&
            cursor.data[cursor.offset] == MTC_DER_EXTENSIONS) {
        MtcCertCursor extensions;

        ret = mtc_cert_read_der(&cursor, MTC_DER_EXTENSIONS, NULL,
            &contents);
        if (ret == 0) {
            extensions.data = contents.data;
            extensions.len = contents.len;
            extensions.offset = 0;
            ret = mtc_cert_read_der(&extensions, MTC_DER_SEQUENCE, NULL,
                NULL);
            if (ret == 0 && extensions.offset != extensions.len)
                ret = ASN_PARSE_E;
        }
    }
    if (ret == 0 && cursor.offset != cursor.len)
        ret = ASN_PARSE_E;

    return ret;
}

static int mtc_cert_parse_tbs(const byte* tbs, size_t tbsLen,
    MtcTbsFields* fields)
{
    MtcTbsFields decoded;
    MtcCertCursor outer;
    MtcCertCursor body;
    MtcCertCursor spki;
    MtcCertSpan bodyContents;
    MtcCertSpan spkiContents;
    MtcCertSpan contents;
    MtcCertSpan ignored;
    int ret;

    XMEMSET(&decoded, 0, sizeof(decoded));
    outer.data = tbs;
    outer.len = tbsLen;
    outer.offset = 0;

    ret = mtc_cert_read_der(&outer, MTC_DER_SEQUENCE, NULL, &bodyContents);
    if (ret == 0 && outer.offset != outer.len)
        ret = ASN_PARSE_E;
    if (ret != 0)
        return ret;

    body.data = bodyContents.data;
    body.len = bodyContents.len;
    body.offset = 0;

    if (body.offset < body.len &&
            body.data[body.offset] == MTC_DER_EXPLICIT_VERSION) {
        MtcCertCursor version;

        ret = mtc_cert_read_der(&body, MTC_DER_EXPLICIT_VERSION,
            &decoded.version, &contents);
        if (ret == 0) {
            version.data = contents.data;
            version.len = contents.len;
            version.offset = 0;
            ret = mtc_cert_read_der(&version, MTC_DER_INTEGER, NULL,
                &contents);
            if (ret == 0)
                ret = mtc_cert_validate_integer(&contents);
            if (ret == 0 && version.offset != version.len)
                ret = ASN_PARSE_E;
        }
    }
    else {
        ret = 0;
    }

    /* serialNumber and signature are not part of TBSCertificateLogEntry. */
    if (ret == 0) {
        ret = mtc_cert_read_der(&body, MTC_DER_INTEGER, &ignored,
            &contents);
        if (ret == 0)
            ret = mtc_cert_validate_integer(&contents);
    }
    if (ret == 0)
        ret = mtc_cert_read_der(&body, MTC_DER_SEQUENCE, &ignored, NULL);
    if (ret == 0) {
        ret = mtc_cert_read_der(&body, MTC_DER_SEQUENCE, &decoded.issuer,
            NULL);
    }
    if (ret == 0) {
        ret = mtc_cert_read_der(&body, MTC_DER_SEQUENCE, &decoded.validity,
            NULL);
    }
    if (ret == 0) {
        ret = mtc_cert_read_der(&body, MTC_DER_SEQUENCE, &decoded.subject,
            NULL);
    }
    if (ret == 0) {
        ret = mtc_cert_read_der(&body, MTC_DER_SEQUENCE,
            &decoded.subjectPublicKeyInfo, &spkiContents);
    }
    if (ret != 0)
        return ret;

    decoded.fieldsAfterSubjectPublicKeyInfo.data = body.data + body.offset;
    decoded.fieldsAfterSubjectPublicKeyInfo.len = body.len - body.offset;
    ret = mtc_cert_validate_tbs_tail(
        &decoded.fieldsAfterSubjectPublicKeyInfo);
    if (ret != 0)
        return ret;

    spki.data = spkiContents.data;
    spki.len = spkiContents.len;
    spki.offset = 0;
    ret = mtc_cert_read_der(&spki, MTC_DER_SEQUENCE,
        &decoded.publicKeyAlgorithm, NULL);
    if (ret == 0) {
        ret = mtc_cert_read_der(&spki, MTC_DER_BIT_STRING, &ignored,
            &contents);
        if (ret == 0)
            ret = mtc_cert_validate_bit_string(&contents);
    }
    if (ret == 0 && spki.offset != spki.len)
        ret = ASN_PARSE_E;
    if (ret == 0)
        *fields = decoded;

    return ret;
}

/* Validate the contents (without the uint16 vector length) of
 * MerkleTreeCertEntryExtension extensions<0..2^16-1>. */
static int mtc_cert_validate_extensions(const byte* extensions,
    size_t extensionsLen)
{
    size_t offset = 0;
    word16 previousType = 0;
    int havePrevious = 0;

    while (offset < extensionsLen) {
        word16 type;
        word16 len;

        if (extensionsLen - offset < 4U)
            return BUFFER_E;
        type = (word16)(((word16)extensions[offset] << 8) |
            extensions[offset + 1U]);
        len = (word16)(((word16)extensions[offset + 2U] << 8) |
            extensions[offset + 3U]);
        offset += 4U;

        if ((size_t)len > extensionsLen - offset)
            return BUFFER_E;
        if (havePrevious && type <= previousType)
            return ASN_PARSE_E;

        previousType = type;
        havePrevious = 1;
        offset += len;
    }

    return 0;
}

static int mtc_cert_add_size(size_t* total, size_t value)
{
    if (value > (size_t)-1 - *total)
        return BUFFER_E;
    *total += value;
    return 0;
}

static size_t mtc_cert_der_header_size(size_t len)
{
    size_t bytes = 1U;

    if (len >= 128U) {
        bytes = 2U;
        while (len > 0xffU) {
            ++bytes;
            len >>= 8;
        }
    }

    return bytes + 1U; /* tag plus DER length */
}

static size_t mtc_cert_write_octet_header(byte* output, size_t len)
{
    size_t lengthBytes = 0;
    size_t i;

    output[0] = MTC_DER_OCTET_STRING;
    if (len < 128U) {
        output[1] = (byte)len;
        return 2U;
    }

    for (i = len; i != 0U; i >>= 8)
        ++lengthBytes;
    output[1] = (byte)(0x80U | lengthBytes);
    for (i = 0; i < lengthBytes; ++i) {
        output[2U + lengthBytes - 1U - i] = (byte)len;
        len >>= 8;
    }

    return 2U + lengthBytes;
}

static void mtc_cert_copy_span(byte* output, size_t* offset,
    const MtcCertSpan* span)
{
    if (span->len != 0U) {
        XMEMCPY(output + *offset, span->data, span->len);
        *offset += span->len;
    }
}

int mtc_cert_entry_from_tbs(byte* entry, size_t* entryLen,
    const byte* tbs, size_t tbsLen, const byte* entryExtensions,
    size_t entryExtensionsLen, enum wc_HashType hashType)
{
    byte digest[WC_MAX_DIGEST_SIZE];
    MtcTbsFields fields;
    size_t required = 4U; /* extensions length and entry type */
    size_t offset = 0;
    size_t octetHeaderLen;
    size_t capacity;
    int digestLen;
    int ret;

    if (entryLen == NULL || tbs == NULL || tbsLen == 0U ||
            (entryExtensions == NULL && entryExtensionsLen != 0U) ||
            entryExtensionsLen > 0xffffU || tbsLen > 0xffffffffU) {
        return BAD_FUNC_ARG;
    }

    digestLen = wc_HashGetDigestSize(hashType);
    if (digestLen <= 0 || digestLen > (int)sizeof(digest))
        return digestLen <= 0 ? digestLen : HASH_TYPE_E;

    ret = mtc_cert_validate_extensions(entryExtensions, entryExtensionsLen);
    if (ret == 0)
        ret = mtc_cert_parse_tbs(tbs, tbsLen, &fields);
    if (ret != 0)
        return ret;

    octetHeaderLen = mtc_cert_der_header_size((size_t)digestLen);
    if (mtc_cert_add_size(&required, entryExtensionsLen) != 0 ||
            mtc_cert_add_size(&required, fields.version.len) != 0 ||
            mtc_cert_add_size(&required, fields.issuer.len) != 0 ||
            mtc_cert_add_size(&required, fields.validity.len) != 0 ||
            mtc_cert_add_size(&required, fields.subject.len) != 0 ||
            mtc_cert_add_size(&required,
                fields.publicKeyAlgorithm.len) != 0 ||
            mtc_cert_add_size(&required, octetHeaderLen) != 0 ||
            mtc_cert_add_size(&required, (size_t)digestLen) != 0 ||
            mtc_cert_add_size(&required,
                fields.fieldsAfterSubjectPublicKeyInfo.len) != 0) {
        return BUFFER_E;
    }

    capacity = entry == NULL ? 0U : *entryLen;
    *entryLen = required;
    if (entry == NULL)
        return LENGTH_ONLY_E;
    if (capacity < required)
        return BUFFER_E;

    ret = wc_Hash(hashType, fields.subjectPublicKeyInfo.data,
        (word32)fields.subjectPublicKeyInfo.len, digest, (word32)digestLen);
    if (ret != 0)
        return ret;

    entry[offset++] = (byte)(entryExtensionsLen >> 8);
    entry[offset++] = (byte)entryExtensionsLen;
    if (entryExtensionsLen != 0U) {
        XMEMCPY(entry + offset, entryExtensions, entryExtensionsLen);
        offset += entryExtensionsLen;
    }
    entry[offset++] = 0;
    entry[offset++] = MTC_TBS_CERT_ENTRY;

    mtc_cert_copy_span(entry, &offset, &fields.version);
    mtc_cert_copy_span(entry, &offset, &fields.issuer);
    mtc_cert_copy_span(entry, &offset, &fields.validity);
    mtc_cert_copy_span(entry, &offset, &fields.subject);
    mtc_cert_copy_span(entry, &offset, &fields.publicKeyAlgorithm);
    offset += mtc_cert_write_octet_header(entry + offset, (size_t)digestLen);
    XMEMCPY(entry + offset, digest, (size_t)digestLen);
    offset += (size_t)digestLen;
    mtc_cert_copy_span(entry, &offset,
        &fields.fieldsAfterSubjectPublicKeyInfo);

    if (offset != required)
        return ASN_PARSE_E;

    return 0;
}

#else

int mtc_cert_entry_from_tbs(byte* entry, size_t* entryLen,
    const byte* tbs, size_t tbsLen, const byte* entryExtensions,
    size_t entryExtensionsLen, enum wc_HashType hashType)
{
    (void)entry;
    (void)entryLen;
    (void)tbs;
    (void)tbsLen;
    (void)entryExtensions;
    (void)entryExtensionsLen;
    (void)hashType;

    return NOT_COMPILED_IN;
}

#endif /* !NO_HASH_WRAPPER */
