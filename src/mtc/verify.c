/* verify.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335,
 * USA
 */

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#include <wolfssl/internal.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/sha256.h>

#include "src/mtc/cosign.h"
#include "src/mtc/mtc_cert.h"
#include "src/mtc/mtc_parse.h"
#include "src/mtc/verify.h"

#if defined(WOLFSSL_MTC) && !defined(NO_SHA256)

enum {
    MTC_VERIFY_DER_INTEGER          = 0x02,
    MTC_VERIFY_DER_BIT_STRING       = 0x03,
    MTC_VERIFY_DER_OBJECT_ID        = 0x06,
    MTC_VERIFY_DER_UTF8_STRING      = 0x0c,
    MTC_VERIFY_DER_SEQUENCE         = 0x30,
    MTC_VERIFY_DER_SET              = 0x31,
    MTC_VERIFY_DER_EXPLICIT_VERSION = 0xa0
};

typedef struct MtcVerifySpan {
    const byte* data;
    size_t len;
} MtcVerifySpan;

typedef struct MtcVerifyCursor {
    const byte* data;
    size_t len;
    size_t offset;
} MtcVerifyCursor;

typedef struct MtcVerifyCertFields {
    MtcVerifySpan tbs;
    MtcVerifySpan serial;
    MtcVerifySpan tbsSignatureAlgorithm;
    MtcVerifySpan issuer;
    MtcVerifySpan subject;
    MtcVerifySpan signatureAlgorithm;
    MtcVerifySpan signature;
} MtcVerifyCertFields;

/* DER value octets for 1.3.6.1.4.1.44363.47.1, the experimental
 * id-rdna-trustAnchorID used by the draft test corpus. */
static const byte mtcVerifyTrustAnchorRdnOid[] = {
    0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xda, 0x4b, 0x2f, 0x01
};

/* Complete DER AlgorithmIdentifier for id-alg-mtcProof with omitted
 * parameters: 1.3.6.1.4.1.44363.47.0. */
static const byte mtcVerifyProofAlgorithm[] = {
    0x30, 0x0c, 0x06, 0x0a,
    0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xda, 0x4b, 0x2f, 0x00
};

static int mtc_verify_read_der(MtcVerifyCursor* cursor, byte expectedTag,
    MtcVerifySpan* encoded, MtcVerifySpan* contents)
{
    size_t start;
    size_t len;
    byte lengthByte;

    if (cursor == NULL || cursor->offset > cursor->len ||
            cursor->len - cursor->offset < 2U) {
        return BUFFER_E;
    }

    start = cursor->offset;
    if (cursor->data[cursor->offset++] != expectedTag)
        return ASN_PARSE_E;

    lengthByte = cursor->data[cursor->offset++];
    if ((lengthByte & 0x80U) == 0U) {
        len = lengthByte;
    }
    else {
        size_t lengthBytes = lengthByte & 0x7fU;
        size_t i;

        if (lengthBytes == 0U || lengthBytes > sizeof(size_t) ||
                lengthBytes > cursor->len - cursor->offset) {
            return ASN_PARSE_E;
        }
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

static int mtc_verify_parse_certificate(const byte* der, size_t derLen,
    MtcVerifyCertFields* fields)
{
    MtcVerifyCertFields decoded;
    MtcVerifyCursor outer;
    MtcVerifyCursor certBody;
    MtcVerifyCursor tbs;
    MtcVerifySpan certificateContents;
    MtcVerifySpan tbsContents;
    MtcVerifySpan bitString;
    MtcVerifySpan ignored;
    int ret;

    if (der == NULL || derLen == 0U || fields == NULL)
        return BAD_FUNC_ARG;

    XMEMSET(&decoded, 0, sizeof(decoded));
    outer.data = der;
    outer.len = derLen;
    outer.offset = 0;
    ret = mtc_verify_read_der(&outer, MTC_VERIFY_DER_SEQUENCE, NULL,
        &certificateContents);
    if (ret == 0 && outer.offset != outer.len)
        ret = ASN_PARSE_E;
    if (ret != 0)
        return ret;

    certBody.data = certificateContents.data;
    certBody.len = certificateContents.len;
    certBody.offset = 0;
    ret = mtc_verify_read_der(&certBody, MTC_VERIFY_DER_SEQUENCE,
        &decoded.tbs, &tbsContents);
    if (ret == 0) {
        ret = mtc_verify_read_der(&certBody, MTC_VERIFY_DER_SEQUENCE,
            &decoded.signatureAlgorithm, NULL);
    }
    if (ret == 0) {
        ret = mtc_verify_read_der(&certBody, MTC_VERIFY_DER_BIT_STRING,
            NULL, &bitString);
    }
    if (ret == 0 && certBody.offset != certBody.len)
        ret = ASN_PARSE_E;
    if (ret == 0 && (bitString.len == 0U || bitString.data[0] != 0U))
        ret = ASN_PARSE_E;
    if (ret != 0)
        return ret;

    decoded.signature.data = bitString.data + 1U;
    decoded.signature.len = bitString.len - 1U;

    tbs.data = tbsContents.data;
    tbs.len = tbsContents.len;
    tbs.offset = 0;
    if (tbs.offset < tbs.len &&
            tbs.data[tbs.offset] == MTC_VERIFY_DER_EXPLICIT_VERSION) {
        ret = mtc_verify_read_der(&tbs, MTC_VERIFY_DER_EXPLICIT_VERSION,
            &ignored, NULL);
    }
    else {
        ret = 0;
    }
    if (ret == 0) {
        ret = mtc_verify_read_der(&tbs, MTC_VERIFY_DER_INTEGER, NULL,
            &decoded.serial);
    }
    if (ret == 0) {
        ret = mtc_verify_read_der(&tbs, MTC_VERIFY_DER_SEQUENCE,
            &decoded.tbsSignatureAlgorithm, NULL);
    }
    if (ret == 0) {
        ret = mtc_verify_read_der(&tbs, MTC_VERIFY_DER_SEQUENCE,
            &decoded.issuer, NULL);
    }
    if (ret == 0) {
        ret = mtc_verify_read_der(&tbs, MTC_VERIFY_DER_SEQUENCE,
            &ignored, NULL); /* validity */
    }
    if (ret == 0) {
        ret = mtc_verify_read_der(&tbs, MTC_VERIFY_DER_SEQUENCE,
            &decoded.subject, NULL);
    }
    if (ret == 0 && (decoded.tbsSignatureAlgorithm.len !=
            decoded.signatureAlgorithm.len ||
            XMEMCMP(decoded.tbsSignatureAlgorithm.data,
                decoded.signatureAlgorithm.data,
                decoded.signatureAlgorithm.len) != 0)) {
        ret = ASN_SIG_OID_E;
    }
    if (ret == 0)
        *fields = decoded;

    return ret;
}

static int mtc_verify_is_proof_algorithm(const MtcVerifySpan* algorithm)
{
    return algorithm != NULL &&
        algorithm->len == sizeof(mtcVerifyProofAlgorithm) &&
        XMEMCMP(algorithm->data, mtcVerifyProofAlgorithm,
            sizeof(mtcVerifyProofAlgorithm)) == 0;
}

static int mtc_verify_serial_u64(const MtcVerifySpan* serial,
    word64* value)
{
    size_t offset = 0;
    word64 decoded = 0;

    if (serial == NULL || value == NULL || serial->len == 0U)
        return ASN_PARSE_E;
    if ((serial->data[0] & 0x80U) != 0U)
        return ASN_PARSE_E;

    if (serial->len > 1U && serial->data[0] == 0U) {
        if ((serial->data[1] & 0x80U) == 0U)
            return ASN_PARSE_E;
        offset = 1U;
    }
    if (serial->len - offset > sizeof(decoded))
        return ASN_PARSE_E;

    while (offset < serial->len)
        decoded = (decoded << 8) | serial->data[offset++];

    *value = decoded;
    return 0;
}

static int mtc_verify_append_id_component(byte* output, size_t outputLen,
    size_t* offset, word32 value)
{
    byte encoded[5];
    size_t len = 0;
    size_t i;

    do {
        encoded[len++] = (byte)(value & 0x7fU);
        value >>= 7;
    } while (value != 0U);

    if (*offset > outputLen || len > outputLen - *offset)
        return BUFFER_E;
    for (i = len; i > 0U; --i) {
        byte next = encoded[i - 1U];

        if (i != 1U)
            next |= 0x80U;
        output[(*offset)++] = next;
    }

    return 0;
}

static int mtc_verify_ascii_id(const byte* ascii, size_t asciiLen,
    byte* id, size_t* idLen)
{
    size_t capacity;
    size_t input = 0;
    size_t output = 0;

    if (ascii == NULL || asciiLen == 0U || id == NULL || idLen == NULL)
        return BAD_FUNC_ARG;

    capacity = *idLen;
    while (input < asciiLen) {
        word32 component = 0;
        size_t digits = 0;
        int ret;

        while (input < asciiLen && ascii[input] != '.') {
            word32 digit;

            if (ascii[input] < '0' || ascii[input] > '9')
                return ASN_PARSE_E;
            digit = (word32)(ascii[input++] - '0');
            if (component > (0xffffffffU - digit) / 10U)
                return ASN_PARSE_E;
            component = component * 10U + digit;
            ++digits;
        }
        if (digits == 0U)
            return ASN_PARSE_E;

        ret = mtc_verify_append_id_component(id, capacity, &output,
            component);
        if (ret != 0)
            return ret;

        if (input < asciiLen) {
            ++input;
            if (input == asciiLen)
                return ASN_PARSE_E;
        }
    }

    if (output == 0U || output > 0xffU)
        return ASN_PARSE_E;
    *idLen = output;
    return 0;
}

static int mtc_verify_id_from_name(const MtcVerifySpan* encodedName,
    byte* id, size_t* idLen)
{
    MtcVerifyCursor outer;
    MtcVerifyCursor name;
    MtcVerifyCursor rdn;
    MtcVerifyCursor attribute;
    MtcVerifySpan nameContents;
    MtcVerifySpan rdnContents;
    MtcVerifySpan attributeContents;
    MtcVerifySpan oid;
    MtcVerifySpan value;
    int ret;

    if (encodedName == NULL || encodedName->data == NULL || id == NULL ||
            idLen == NULL) {
        return BAD_FUNC_ARG;
    }

    XMEMSET(&nameContents, 0, sizeof(nameContents));
    XMEMSET(&rdnContents, 0, sizeof(rdnContents));
    XMEMSET(&attributeContents, 0, sizeof(attributeContents));
    outer.data = encodedName->data;
    outer.len = encodedName->len;
    outer.offset = 0;
    ret = mtc_verify_read_der(&outer, MTC_VERIFY_DER_SEQUENCE, NULL,
        &nameContents);
    if (ret == 0 && outer.offset != outer.len)
        ret = ASN_PARSE_E;

    name.data = nameContents.data;
    name.len = nameContents.len;
    name.offset = 0;
    if (ret == 0) {
        ret = mtc_verify_read_der(&name, MTC_VERIFY_DER_SET, NULL,
            &rdnContents);
    }
    if (ret == 0 && name.offset != name.len)
        ret = ASN_PARSE_E;

    rdn.data = rdnContents.data;
    rdn.len = rdnContents.len;
    rdn.offset = 0;
    if (ret == 0) {
        ret = mtc_verify_read_der(&rdn, MTC_VERIFY_DER_SEQUENCE, NULL,
            &attributeContents);
    }
    if (ret == 0 && rdn.offset != rdn.len)
        ret = ASN_PARSE_E;

    attribute.data = attributeContents.data;
    attribute.len = attributeContents.len;
    attribute.offset = 0;
    if (ret == 0) {
        ret = mtc_verify_read_der(&attribute, MTC_VERIFY_DER_OBJECT_ID, NULL,
            &oid);
    }
    if (ret == 0) {
        ret = mtc_verify_read_der(&attribute, MTC_VERIFY_DER_UTF8_STRING,
            NULL, &value);
    }
    if (ret == 0 && attribute.offset != attribute.len)
        ret = ASN_PARSE_E;
    if (ret == 0 && (oid.len != sizeof(mtcVerifyTrustAnchorRdnOid) ||
            XMEMCMP(oid.data, mtcVerifyTrustAnchorRdnOid,
                sizeof(mtcVerifyTrustAnchorRdnOid)) != 0)) {
        ret = ASN_PARSE_E;
    }
    if (ret == 0)
        ret = mtc_verify_ascii_id(value.data, value.len, id, idLen);

    return ret;
}

int mtc_ca_id_from_cert(const WOLFSSL_X509* ca, byte* id, size_t* idLen)
{
    MtcVerifyCertFields fields;
    int ret;

    WOLFSSL_ENTER("mtc_ca_id_from_cert");

    if (ca == NULL || id == NULL || idLen == NULL || ca->derCert == NULL)
        return BAD_FUNC_ARG;

    ret = mtc_verify_parse_certificate(ca->derCert->buffer,
        ca->derCert->length, &fields);
    if (ret == 0)
        ret = mtc_verify_id_from_name(&fields.subject, id, idLen);

    WOLFSSL_LEAVE("mtc_ca_id_from_cert", ret);
    return ret;
}

int mtc_ca_id_from_issuer(const WOLFSSL_X509* cert, byte* id, size_t* idLen)
{
    MtcVerifyCertFields fields;
    int ret;

    WOLFSSL_ENTER("mtc_ca_id_from_issuer");

    if (cert == NULL || id == NULL || idLen == NULL ||
            cert->derCert == NULL) {
        return BAD_FUNC_ARG;
    }

    ret = mtc_verify_parse_certificate(cert->derCert->buffer,
        cert->derCert->length, &fields);
    if (ret == 0)
        ret = mtc_verify_id_from_name(&fields.issuer, id, idLen);

    WOLFSSL_LEAVE("mtc_ca_id_from_issuer", ret);
    return ret;
}

static int mtc_verify_make_log_id(byte* logId, size_t* logIdLen,
    const byte* caId, size_t caIdLen, word32 logNumber)
{
    size_t capacity;
    size_t offset;
    int ret;

    if (logId == NULL || logIdLen == NULL || caId == NULL || caIdLen == 0U ||
            caIdLen > 0xffU || logNumber == 0U || logNumber > 0xffffU) {
        return BAD_FUNC_ARG;
    }

    capacity = *logIdLen;
    if (caIdLen > capacity)
        return BUFFER_E;
    XMEMCPY(logId, caId, caIdLen);
    offset = caIdLen;

    ret = mtc_verify_append_id_component(logId, capacity, &offset, 0);
    if (ret == 0) {
        ret = mtc_verify_append_id_component(logId, capacity, &offset,
            logNumber);
    }
    if (ret == 0 && offset > 0xffU)
        ret = BUFFER_E;
    if (ret == 0)
        *logIdLen = offset;

    return ret;
}

static int mtc_verify_compare_ids(const byte* left, size_t leftLen,
    const byte* right, size_t rightLen)
{
    int compared;

    if (leftLen < rightLen)
        return -1;
    if (leftLen > rightLen)
        return 1;

    compared = XMEMCMP(left, right, leftLen);
    return compared < 0 ? -1 : compared > 0 ? 1 : 0;
}

/* Validate the MerkleTreeCertEntryExtension vector. Extension types are
 * uint16 values and must be strictly increasing. */
static int mtc_verify_validate_extensions(const byte* extensions,
    size_t extensionsLen)
{
    size_t offset = 0;
    word32 previousType = 0;
    int havePrevious = 0;

    if (extensions == NULL && extensionsLen != 0U)
        return BAD_FUNC_ARG;

    while (offset < extensionsLen) {
        word32 type;
        size_t dataLen;

        if (extensionsLen - offset < 4U)
            return ASN_PARSE_E;
        type = ((word32)extensions[offset] << 8) |
            extensions[offset + 1U];
        dataLen = ((size_t)extensions[offset + 2U] << 8) |
            extensions[offset + 3U];
        offset += 4U;

        if (havePrevious && type <= previousType)
            return ASN_PARSE_E;
        if (dataLen > extensionsLen - offset)
            return ASN_PARSE_E;

        previousType = type;
        havePrevious = 1;
        offset += dataLen;
    }

    return 0;
}

static int mtc_verify_find_signature(const byte* signatures,
    size_t signaturesLen, const byte* wantedId, size_t wantedIdLen,
    const byte** signature, size_t* signatureLen)
{
    const byte* previousId = NULL;
    size_t previousIdLen = 0;
    size_t offset = 0;

    if ((signatures == NULL && signaturesLen != 0U) || wantedId == NULL ||
            wantedIdLen == 0U || signature == NULL || signatureLen == NULL) {
        return BAD_FUNC_ARG;
    }

    *signature = NULL;
    *signatureLen = 0;
    while (offset < signaturesLen) {
        const byte* id;
        const byte* value;
        size_t idLen;
        size_t valueLen;

        if (signaturesLen - offset < 1U)
            return BUFFER_E;
        idLen = signatures[offset++];
        if (idLen == 0U || idLen > signaturesLen - offset)
            return ASN_PARSE_E;
        id = signatures + offset;
        offset += idLen;

        if (signaturesLen - offset < 2U)
            return BUFFER_E;
        valueLen = ((size_t)signatures[offset] << 8) |
            signatures[offset + 1U];
        offset += 2U;
        if (valueLen > signaturesLen - offset)
            return BUFFER_E;
        value = signatures + offset;
        offset += valueLen;

        if (previousId != NULL && mtc_verify_compare_ids(previousId,
                previousIdLen, id, idLen) >= 0) {
            return ASN_PARSE_E;
        }
        previousId = id;
        previousIdLen = idLen;

        if (idLen == wantedIdLen &&
                XMEMCMP(id, wantedId, wantedIdLen) == 0) {
            *signature = value;
            *signatureLen = valueLen;
        }
    }

    return 0;
}

static int mtc_verify_signature_or_subtree(const WOLFSSL_X509* cert,
    const WOLFSSL_X509* issuer, word32 trustedLogNumber,
    const byte* trustedSubtreeHash, size_t trustedSubtreeHashLen)
{
    MtcVerifyCertFields certFields;
    MtcVerifyCertFields issuerFields;
    MTCProof proof;
    byte caId[0xffU];
    byte logId[0xffU];
    byte subtreeHash[WC_SHA256_DIGEST_SIZE];
    const byte* cosignature = NULL;
    byte* entry = NULL;
    byte* message = NULL;
    size_t caIdLen = sizeof(caId);
    size_t logIdLen = sizeof(logId);
    size_t cosignatureLen = 0;
    size_t entryLen = 0;
    size_t messageLen = 0;
    word64 serial = 0;
    word64 index;
    word32 logNumber;
    void* heap;
    int decodedInitialized = 0;
    int verifyTrustedSubtree = trustedSubtreeHash != NULL;
    int ret;
    WC_DECLARE_VAR(decodedIssuer, DecodedCert, 1, 0);

    WOLFSSL_ENTER("mtc_verify_signature_or_subtree");

    if (cert == NULL || issuer == NULL || cert->derCert == NULL ||
            issuer->derCert == NULL) {
        return BAD_FUNC_ARG;
    }
    if ((!verifyTrustedSubtree && trustedSubtreeHashLen != 0U) ||
            (verifyTrustedSubtree &&
                (trustedSubtreeHashLen != WC_SHA256_DIGEST_SIZE ||
                 trustedLogNumber == 0U || trustedLogNumber > 0xffffU))) {
        return BAD_FUNC_ARG;
    }
    heap = cert->heap;

    ret = mtc_verify_parse_certificate(cert->derCert->buffer,
        cert->derCert->length, &certFields);
    if (ret == 0) {
        ret = mtc_verify_parse_certificate(issuer->derCert->buffer,
            issuer->derCert->length, &issuerFields);
    }
    if (ret == 0 && (!mtc_verify_is_proof_algorithm(
            &certFields.tbsSignatureAlgorithm) ||
            cert->sigOID != CTC_MTC_PROOF)) {
        ret = ASN_SIG_OID_E;
    }
    if (ret == 0 && (certFields.issuer.len != issuerFields.subject.len ||
            XMEMCMP(certFields.issuer.data, issuerFields.subject.data,
                issuerFields.subject.len) != 0)) {
        ret = ASN_NO_SIGNER_E;
    }
    if (ret == 0)
        ret = mtc_verify_serial_u64(&certFields.serial, &serial);
    if (ret == 0) {
        index = serial & W64LIT(0x0000ffffffffffff);
        logNumber = (word32)(serial >> 48);
        if (logNumber == 0U)
            ret = ASN_PARSE_E;
    }

    if (ret == 0) {
        ret = mtc_verify_id_from_name(&issuerFields.subject, caId, &caIdLen);
    }
    if (ret == 0 && !verifyTrustedSubtree) {
        ret = mtc_verify_make_log_id(logId, &logIdLen, caId, caIdLen,
            logNumber);
    }
    if (ret == 0 && mtc_proof_parse(&proof, certFields.signature.data,
            certFields.signature.len) != 0) {
        ret = ASN_PARSE_E;
    }
    if (ret == 0) {
        ret = mtc_verify_validate_extensions(proof.extensions,
            proof.extensions_len);
    }
    if (ret == 0) {
        ret = mtc_verify_find_signature(proof.signatures,
            proof.signatures_len, caId, caIdLen, &cosignature,
            &cosignatureLen);
        if (ret == 0 && !verifyTrustedSubtree && cosignature == NULL)
            ret = ASN_NO_SIGNER_E;
        if (ret == 0 && !verifyTrustedSubtree && cosignatureLen == 0U)
            ret = ASN_SIG_CONFIRM_E;
    }

    if (ret == 0) {
        WC_ALLOC_VAR_EX(decodedIssuer, DecodedCert, 1, issuer->heap,
            DYNAMIC_TYPE_DCERT, ret = MEMORY_E);
        if (WC_VAR_OK(decodedIssuer)) {
            InitDecodedCert(decodedIssuer, issuer->derCert->buffer,
                issuer->derCert->length, issuer->heap);
            decodedInitialized = 1;
            ret = ParseCertRelative(decodedIssuer, CA_TYPE, NO_VERIFY, NULL,
                NULL);
        }
    }
    if (ret == 0 && (!decodedIssuer->extBasicConstSet ||
            !decodedIssuer->isCA || !decodedIssuer->extKeyUsageSet ||
            (decodedIssuer->extKeyUsage & KEYUSE_KEY_CERT_SIGN) == 0U ||
            !decodedIssuer->extMtcCaSet || !decodedIssuer->extMtcCaCrit)) {
        ret = ASN_NO_SIGNER_E;
    }
    if (ret == 0 && decodedIssuer->extMtcCaLogHashOID != SHA256h)
        ret = NOT_COMPILED_IN;
    if (ret == 0 && (decodedIssuer->extMtcCaMinSerial >
            decodedIssuer->extMtcCaMaxSerial ||
            serial < decodedIssuer->extMtcCaMinSerial ||
            serial > decodedIssuer->extMtcCaMaxSerial)) {
        ret = ASN_SIG_CONFIRM_E;
    }
    if (ret == 0 && (decodedIssuer->publicKey == NULL ||
            decodedIssuer->pubKeySize == 0U)) {
        ret = ASN_NO_SIGNER_E;
    }

    if (ret == 0) {
        ret = mtc_cert_entry_from_tbs(NULL, &entryLen, certFields.tbs.data,
            certFields.tbs.len, proof.extensions, proof.extensions_len,
            WC_HASH_TYPE_SHA256);
        if (ret == LENGTH_ONLY_E)
            ret = 0;
    }
    if (ret == 0) {
        entry = (byte*)XMALLOC(entryLen, heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (entry == NULL)
            ret = MEMORY_E;
    }
    if (ret == 0) {
        Entry entryView;

        ret = mtc_cert_entry_from_tbs(entry, &entryLen, certFields.tbs.data,
            certFields.tbs.len, proof.extensions, proof.extensions_len,
            WC_HASH_TYPE_SHA256);
        if (ret == 0) {
            entryView.data = entry;
            entryView.length = entryLen;
            hash_leaf(subtreeHash, &entryView);
        }
    }
    if (ret == 0 &&
            (proof.inclusion_proof_len % WC_SHA256_DIGEST_SIZE) != 0U) {
        ret = ASN_PARSE_E;
    }
    if (ret == 0 && evaluate_inclusion_proof(index, proof.start, proof.end,
            subtreeHash, proof.inclusion_proof,
            proof.inclusion_proof_len / WC_SHA256_DIGEST_SIZE) != 0) {
        ret = ASN_PARSE_E;
    }
    if (ret == 0 && verifyTrustedSubtree &&
            (logNumber != trustedLogNumber ||
             XMEMCMP(subtreeHash, trustedSubtreeHash,
                 WC_SHA256_DIGEST_SIZE) != 0)) {
        ret = ASN_SIG_CONFIRM_E;
    }

    if (ret == 0 && !verifyTrustedSubtree) {
        ret = mtc_cosigned_message_create(NULL, &messageLen, caId, caIdLen,
            0, logId, logIdLen, proof.start, proof.end, subtreeHash,
            sizeof(subtreeHash));
        if (ret == LENGTH_ONLY_E)
            ret = 0;
    }
    if (ret == 0 && !verifyTrustedSubtree) {
        message = (byte*)XMALLOC(messageLen, heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (message == NULL)
            ret = MEMORY_E;
    }
    if (ret == 0 && !verifyTrustedSubtree) {
        ret = mtc_cosigned_message_create(message, &messageLen, caId,
            caIdLen, 0, logId, logIdLen, proof.start, proof.end,
            subtreeHash, sizeof(subtreeHash));
    }
    if (ret == 0 && !verifyTrustedSubtree && messageLen > 0xffffffffU)
        ret = BUFFER_E;

    if (ret == 0 && !verifyTrustedSubtree) {
        WC_DECLARE_VAR(signatureCtx, SignatureCtx, 1, 0);

        WC_ALLOC_VAR_EX(signatureCtx, SignatureCtx, 1, heap,
            DYNAMIC_TYPE_SIGNATURE, ret = MEMORY_E);
        if (WC_VAR_OK(signatureCtx)) {
            InitSignatureCtx(signatureCtx, heap, INVALID_DEVID);
            ret = ConfirmSignature(signatureCtx, message, (word32)messageLen,
                decodedIssuer->publicKey, decodedIssuer->pubKeySize,
                decodedIssuer->keyOID, cosignature, (word32)cosignatureLen,
                decodedIssuer->extMtcCaSigOID, NULL, 0, NULL);
            FreeSignatureCtx(signatureCtx);
            WC_FREE_VAR_EX(signatureCtx, heap, DYNAMIC_TYPE_SIGNATURE);
        }
    }

    XFREE(message, heap, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(entry, heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (decodedInitialized)
        FreeDecodedCert(decodedIssuer);
    WC_FREE_VAR_EX(decodedIssuer, issuer->heap, DYNAMIC_TYPE_DCERT);

    WOLFSSL_LEAVE("mtc_verify_signature_or_subtree", ret);
    return ret;
}

int mtc_verify_trusted_subtree(const WOLFSSL_X509* cert,
    const WOLFSSL_X509* issuer, word32 logNumber,
    const byte* trustedSubtreeHash, size_t trustedSubtreeHashLen)
{
    return mtc_verify_signature_or_subtree(cert, issuer, logNumber,
        trustedSubtreeHash, trustedSubtreeHashLen);
}

int mtc_verify_cosignature(const WOLFSSL_X509* cert,
    const WOLFSSL_X509* issuer)
{
    return mtc_verify_signature_or_subtree(cert, issuer, 0, NULL, 0);
}

#elif defined(WOLFSSL_MTC)

int mtc_ca_id_from_cert(const WOLFSSL_X509* ca, byte* id, size_t* idLen)
{
    (void)ca;
    (void)id;
    (void)idLen;
    return NOT_COMPILED_IN;
}

int mtc_ca_id_from_issuer(const WOLFSSL_X509* cert, byte* id, size_t* idLen)
{
    (void)cert;
    (void)id;
    (void)idLen;
    return NOT_COMPILED_IN;
}

int mtc_verify_trusted_subtree(const WOLFSSL_X509* cert,
    const WOLFSSL_X509* issuer, word32 logNumber,
    const byte* trustedSubtreeHash, size_t trustedSubtreeHashLen)
{
    (void)cert;
    (void)issuer;
    (void)logNumber;
    (void)trustedSubtreeHash;
    (void)trustedSubtreeHashLen;
    return NOT_COMPILED_IN;
}

int mtc_verify_cosignature(const WOLFSSL_X509* cert,
    const WOLFSSL_X509* issuer)
{
    (void)cert;
    (void)issuer;
    return NOT_COMPILED_IN;
}

#endif /* WOLFSSL_MTC && !NO_SHA256 */
