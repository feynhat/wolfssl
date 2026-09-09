/* mtc_inclusion_proof.c
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1335, USA
 */

/*
 * Extract the inclusion_proof vector from the TLS-encoded MTCProof carried
 * directly in an id-alg-mtcProof X.509 signatureValue. The example also
 * reconstructs the MerkleTreeCertEntry and prints its SHA-256 Merkle leaf
 * hash. It does not evaluate the Merkle path or verify any cosignatures.
 *
 * Build from the wolfSSL source directory with, for example:
 *
 *   cc -I. examples/mtc/mtc_inclusion_proof.c -Lsrc/.libs \
 *      -Wl,-rpath,"$PWD/src/.libs" -lwolfssl -o mtc_inclusion_proof
 *
 * Usage:
 *
 *   ./mtc_inclusion_proof [--brief] [--draft-03|--draft-05] \
 *      [--hash-size bytes] certificate.pem
 *
 * With no hash-size, the inclusion proof is printed as one byte string. When
 * hash-size is supplied, each fixed-size HashValue is printed separately.
 * HASH_SIZE is determined by the issuing MTC CA's logHash algorithm, not by
 * the leaf certificate, so this example does not guess it.
 *
 * --brief prints one value per line: the MerkleTreeCertEntry leaf hash, entry
 * index, subtree start, subtree end, and then the inclusion-proof hashes.
 * Supply --hash-size to split the inclusion proof into individual hashes;
 * otherwise its bytes use one line.
 *
 * By default, the example tries the draft-05 layout first and then the older
 * draft-03 layout. --draft-03 or --draft-05 selects one layout strictly.
 * Draft-03 has uint64 start and end fields and no extensions vector.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif

#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/sha256.h>

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct MtcSpan {
    const unsigned char* data;
    size_t length;
} MtcSpan;

typedef struct MtcCursor {
    const unsigned char* data;
    size_t length;
    size_t offset;
} MtcCursor;

typedef struct MtcProofView {
    MtcSpan extensions;
    uint64_t start;
    uint64_t end;
    MtcSpan inclusionProof;
    MtcSpan signatures;
} MtcProofView;

typedef struct MtcTbsView {
    MtcSpan version;
    MtcSpan issuer;
    MtcSpan validity;
    MtcSpan subject;
    MtcSpan publicKeyAlgorithm;
    MtcSpan subjectPublicKeyInfo;
    MtcSpan fieldsAfterSubjectPublicKeyInfo;
} MtcTbsView;

enum {
    MTC_PARSE_OK = 0,
    MTC_PARSE_BAD_ARGUMENT = -1,
    MTC_PARSE_TRUNCATED = -2,
    MTC_PARSE_MALFORMED = -3,
    MTC_PARSE_TRAILING_DATA = -4,
    MTC_PARSE_COSIGNER_ORDER = -5
};

enum {
    MTC_DER_INTEGER = 0x02,
    MTC_DER_BIT_STRING = 0x03,
    MTC_DER_OCTET_STRING = 0x04,
    MTC_DER_SEQUENCE = 0x30,
    MTC_DER_EXPLICIT_VERSION = 0xa0
};

static int MtcReadBytes(MtcCursor* cursor, size_t length, MtcSpan* value)
{
    if (length > cursor->length - cursor->offset) {
        return MTC_PARSE_TRUNCATED;
    }

    value->data = cursor->data + cursor->offset;
    value->length = length;
    cursor->offset += length;

    return MTC_PARSE_OK;
}

static int MtcReadUint16(MtcCursor* cursor, size_t* value)
{
    if (cursor->length - cursor->offset < 2U) {
        return MTC_PARSE_TRUNCATED;
    }

    *value = ((size_t)cursor->data[cursor->offset] << 8) |
             (size_t)cursor->data[cursor->offset + 1U];
    cursor->offset += 2U;

    return MTC_PARSE_OK;
}

static int MtcReadUint48(MtcCursor* cursor, uint64_t* value)
{
    unsigned int i;

    if (cursor->length - cursor->offset < 6U) {
        return MTC_PARSE_TRUNCATED;
    }

    *value = 0;
    for (i = 0; i < 6U; i++) {
        *value = (*value << 8) | cursor->data[cursor->offset++];
    }

    return MTC_PARSE_OK;
}

static int MtcReadUint64(MtcCursor* cursor, uint64_t* value)
{
    unsigned int i;

    if (cursor->length - cursor->offset < 8U) {
        return MTC_PARSE_TRUNCATED;
    }

    *value = 0;
    for (i = 0; i < 8U; i++) {
        *value = (*value << 8) | cursor->data[cursor->offset++];
    }

    return MTC_PARSE_OK;
}

static int MtcReadVector16(MtcCursor* cursor, MtcSpan* value)
{
    size_t length;
    int ret;

    ret = MtcReadUint16(cursor, &length);
    if (ret == MTC_PARSE_OK) {
        ret = MtcReadBytes(cursor, length, value);
    }

    return ret;
}

static int MtcReadVector8NonEmpty(MtcCursor* cursor, MtcSpan* value)
{
    size_t length;

    if (cursor->length - cursor->offset < 1U) {
        return MTC_PARSE_TRUNCATED;
    }

    length = cursor->data[cursor->offset++];
    if (length == 0U) {
        return MTC_PARSE_MALFORMED;
    }

    return MtcReadBytes(cursor, length, value);
}

/* Validate the contents of
 * MerkleTreeCertEntryExtension extensions<0..2^16-1>.
 */
static int MtcValidateExtensions(const MtcSpan* extensions)
{
    MtcCursor cursor;

    cursor.data = extensions->data;
    cursor.length = extensions->length;
    cursor.offset = 0;

    while (cursor.offset < cursor.length) {
        MtcSpan extensionData;
        size_t extensionType;
        int ret;

        ret = MtcReadUint16(&cursor, &extensionType);
        if (ret != MTC_PARSE_OK) {
            return ret;
        }
        (void)extensionType;

        ret = MtcReadVector16(&cursor, &extensionData);
        if (ret != MTC_PARSE_OK) {
            return ret;
        }
    }

    return MTC_PARSE_OK;
}

/* Validate the contents of MTCSignature signatures<0..2^16-1>, including
 * the draft's strict ordering requirement for cosigner_id values.
 */
static int MtcValidateSignatures(const MtcSpan* signatures)
{
    MtcCursor cursor;
    MtcSpan previousId;
    int havePrevious = 0;

    cursor.data = signatures->data;
    cursor.length = signatures->length;
    cursor.offset = 0;
    previousId.data = NULL;
    previousId.length = 0;

    while (cursor.offset < cursor.length) {
        MtcSpan cosignerId;
        MtcSpan signature;
        int ret;

        ret = MtcReadVector8NonEmpty(&cursor, &cosignerId);
        if (ret != MTC_PARSE_OK) {
            return ret;
        }

        ret = MtcReadVector16(&cursor, &signature);
        if (ret != MTC_PARSE_OK) {
            return ret;
        }
        (void)signature;

        if (havePrevious) {
            if (previousId.length > cosignerId.length ||
                    (previousId.length == cosignerId.length &&
                     memcmp(previousId.data, cosignerId.data,
                            cosignerId.length) >= 0)) {
                return MTC_PARSE_COSIGNER_ORDER;
            }
        }

        previousId = cosignerId;
        havePrevious = 1;
    }

    return MTC_PARSE_OK;
}

static int MtcFinishProof(MtcCursor* cursor, MtcProofView* decoded,
    MtcProofView* proof)
{
    int ret = MTC_PARSE_OK;

    if (cursor->offset != cursor->length) {
        ret = MTC_PARSE_TRAILING_DATA;
    }
    if (ret == MTC_PARSE_OK) {
        ret = MtcValidateExtensions(&decoded->extensions);
    }
    if (ret == MTC_PARSE_OK) {
        ret = MtcValidateSignatures(&decoded->signatures);
    }
    if (ret == MTC_PARSE_OK) {
        *proof = *decoded;
    }

    return ret;
}

/* Decode an MTCProof and return zero-copy views into signatureValue.
 *
 * The caller must keep signatureValue alive while using the returned spans.
 * HASH_SIZE is intentionally not needed to extract inclusion_proof: its TLS
 * vector carries its total byte length. A caller that wants individual
 * HashValue elements must obtain HASH_SIZE from the issuing CA's logHash.
 */
int MtcExtractInclusionProof(const unsigned char* signatureValue,
    size_t signatureValueLength, MtcProofView* proof)
{
    MtcProofView decoded;
    MtcCursor cursor;
    int ret;

    if (signatureValue == NULL || proof == NULL) {
        return MTC_PARSE_BAD_ARGUMENT;
    }

    cursor.data = signatureValue;
    cursor.length = signatureValueLength;
    cursor.offset = 0;

    ret = MtcReadVector16(&cursor, &decoded.extensions);
    if (ret == MTC_PARSE_OK) {
        ret = MtcReadUint48(&cursor, &decoded.start);
    }
    if (ret == MTC_PARSE_OK) {
        ret = MtcReadUint48(&cursor, &decoded.end);
    }
    if (ret == MTC_PARSE_OK) {
        ret = MtcReadVector16(&cursor, &decoded.inclusionProof);
    }
    if (ret == MTC_PARSE_OK) {
        ret = MtcReadVector16(&cursor, &decoded.signatures);
    }
    if (ret == MTC_PARSE_OK) {
        ret = MtcFinishProof(&cursor, &decoded, proof);
    }

    return ret;
}

/* Decode the MTCProof layout from draft-ietf-plants-merkle-tree-certs-03.
 * That version has no extensions vector and encodes start and end as uint64.
 */
int MtcExtractInclusionProofDraft03(const unsigned char* signatureValue,
    size_t signatureValueLength, MtcProofView* proof)
{
    MtcProofView decoded;
    MtcCursor cursor;
    int ret;

    if (signatureValue == NULL || proof == NULL) {
        return MTC_PARSE_BAD_ARGUMENT;
    }

    cursor.data = signatureValue;
    cursor.length = signatureValueLength;
    cursor.offset = 0;
    decoded.extensions.data = NULL;
    decoded.extensions.length = 0;

    ret = MtcReadUint64(&cursor, &decoded.start);
    if (ret == MTC_PARSE_OK) {
        ret = MtcReadUint64(&cursor, &decoded.end);
    }
    if (ret == MTC_PARSE_OK) {
        ret = MtcReadVector16(&cursor, &decoded.inclusionProof);
    }
    if (ret == MTC_PARSE_OK) {
        ret = MtcReadVector16(&cursor, &decoded.signatures);
    }
    if (ret == MTC_PARSE_OK) {
        ret = MtcFinishProof(&cursor, &decoded, proof);
    }

    return ret;
}

/* Read one single-tag DER element, retaining both its complete encoding and
 * its contents octets. Only the low-tag-number form is needed for the X.509
 * fields parsed by this example.
 */
static int MtcReadDerElement(MtcCursor* cursor, int expectedTag,
    MtcSpan* encoded, MtcSpan* contents)
{
    size_t start;
    size_t length;
    unsigned char tag;
    unsigned char lengthByte;

    if (cursor->offset > cursor->length ||
            cursor->length - cursor->offset < 2U) {
        return MTC_PARSE_TRUNCATED;
    }

    start = cursor->offset;
    tag = cursor->data[cursor->offset++];
    if ((tag & 0x1fU) == 0x1fU ||
            (expectedTag >= 0 && tag != (unsigned int)expectedTag)) {
        return MTC_PARSE_MALFORMED;
    }

    lengthByte = cursor->data[cursor->offset++];
    if ((lengthByte & 0x80U) == 0U) {
        length = lengthByte;
    }
    else {
        size_t lengthOctets = lengthByte & 0x7fU;
        size_t i;

        if (lengthOctets == 0U || lengthOctets > sizeof(size_t)) {
            return MTC_PARSE_MALFORMED;
        }
        if (lengthOctets > cursor->length - cursor->offset) {
            return MTC_PARSE_TRUNCATED;
        }
        if (cursor->data[cursor->offset] == 0U) {
            return MTC_PARSE_MALFORMED;
        }

        length = 0;
        for (i = 0; i < lengthOctets; i++) {
            unsigned char value = cursor->data[cursor->offset++];

            if (length > (SIZE_MAX - value) / 256U) {
                return MTC_PARSE_MALFORMED;
            }
            length = length * 256U + value;
        }
        if (length < 128U) {
            return MTC_PARSE_MALFORMED;
        }
    }

    if (length > cursor->length - cursor->offset) {
        return MTC_PARSE_TRUNCATED;
    }

    if (contents != NULL) {
        contents->data = cursor->data + cursor->offset;
        contents->length = length;
    }
    cursor->offset += length;
    if (encoded != NULL) {
        encoded->data = cursor->data + start;
        encoded->length = cursor->offset - start;
    }

    return MTC_PARSE_OK;
}

/* Locate the exact DER encodings used to reconstruct a
 * TBSCertificateLogEntry from a TBSCertificate.
 */
static int MtcParseTbsCertificate(const unsigned char* tbs,
    size_t tbsLength, MtcTbsView* fields)
{
    MtcTbsView decoded;
    MtcCursor outer;
    MtcCursor contents;
    MtcCursor spki;
    MtcSpan tbsContents;
    MtcSpan spkiContents;
    MtcSpan ignored;
    int ret;

    if (tbs == NULL || fields == NULL) {
        return MTC_PARSE_BAD_ARGUMENT;
    }

    memset(&decoded, 0, sizeof(decoded));
    outer.data = tbs;
    outer.length = tbsLength;
    outer.offset = 0;

    ret = MtcReadDerElement(&outer, MTC_DER_SEQUENCE, NULL, &tbsContents);
    if (ret == MTC_PARSE_OK && outer.offset != outer.length) {
        ret = MTC_PARSE_TRAILING_DATA;
    }
    if (ret != MTC_PARSE_OK) {
        return ret;
    }

    contents.data = tbsContents.data;
    contents.length = tbsContents.length;
    contents.offset = 0;
    ret = MTC_PARSE_OK;

    if (contents.offset < contents.length &&
            contents.data[contents.offset] == MTC_DER_EXPLICIT_VERSION) {
        ret = MtcReadDerElement(&contents, MTC_DER_EXPLICIT_VERSION,
            &decoded.version, NULL);
    }
    if (ret == MTC_PARSE_OK) {
        ret = MtcReadDerElement(&contents, MTC_DER_INTEGER, &ignored, NULL);
    }
    if (ret == MTC_PARSE_OK) {
        ret = MtcReadDerElement(&contents, MTC_DER_SEQUENCE, &ignored, NULL);
    }
    if (ret == MTC_PARSE_OK) {
        ret = MtcReadDerElement(&contents, MTC_DER_SEQUENCE,
            &decoded.issuer, NULL);
    }
    if (ret == MTC_PARSE_OK) {
        ret = MtcReadDerElement(&contents, MTC_DER_SEQUENCE,
            &decoded.validity, NULL);
    }
    if (ret == MTC_PARSE_OK) {
        ret = MtcReadDerElement(&contents, MTC_DER_SEQUENCE,
            &decoded.subject, NULL);
    }
    if (ret == MTC_PARSE_OK) {
        ret = MtcReadDerElement(&contents, MTC_DER_SEQUENCE,
            &decoded.subjectPublicKeyInfo, &spkiContents);
    }
    if (ret != MTC_PARSE_OK) {
        return ret;
    }

    decoded.fieldsAfterSubjectPublicKeyInfo.data =
        contents.data + contents.offset;
    decoded.fieldsAfterSubjectPublicKeyInfo.length =
        contents.length - contents.offset;

    spki.data = spkiContents.data;
    spki.length = spkiContents.length;
    spki.offset = 0;
    ret = MtcReadDerElement(&spki, MTC_DER_SEQUENCE,
        &decoded.publicKeyAlgorithm, NULL);
    if (ret == MTC_PARSE_OK) {
        ret = MtcReadDerElement(&spki, MTC_DER_BIT_STRING, &ignored, NULL);
    }
    if (ret == MTC_PARSE_OK && spki.offset != spki.length) {
        ret = MTC_PARSE_TRAILING_DATA;
    }
    if (ret == MTC_PARSE_OK) {
        *fields = decoded;
    }

    return ret;
}

static int MtcSha256Update(wc_Sha256* sha256, const unsigned char* data,
    size_t length)
{
    if (length == 0U) {
        return 0;
    }
    if (data == NULL || length > UINT32_MAX) {
        return MTC_PARSE_BAD_ARGUMENT;
    }

    return wc_Sha256Update(sha256, data, (word32)length);
}

static int MtcSha256Span(const MtcSpan* input,
    unsigned char output[WC_SHA256_DIGEST_SIZE])
{
    wc_Sha256 sha256;
    int ret;

    if (input == NULL || output == NULL) {
        return MTC_PARSE_BAD_ARGUMENT;
    }

    ret = wc_InitSha256(&sha256);
    if (ret == 0) {
        ret = MtcSha256Update(&sha256, input->data, input->length);
        if (ret == 0) {
            ret = wc_Sha256Final(&sha256, output);
        }
        wc_Sha256Free(&sha256);
    }

    return ret;
}

/* Calculate HASH(0x00 || MerkleTreeCertEntry) using SHA-256 and the
 * single-pass construction from the MTC draft. The draft-05 entry begins
 * with the MTCProof extensions vector. Draft-03 has no entry extensions.
 */
static int MtcCalculateEntryHash(const unsigned char* tbs, size_t tbsLength,
    const MtcProofView* proof, int draftVersion,
    unsigned char entryHash[WC_SHA256_DIGEST_SIZE])
{
    static const unsigned char domainSeparator = 0x00;
    static const unsigned char tbsCertEntry[] = {0x00, 0x01};
    static const unsigned char spkiHashHeader[] = {
        MTC_DER_OCTET_STRING, WC_SHA256_DIGEST_SIZE
    };
    unsigned char extensionsLength[2];
    unsigned char spkiHash[WC_SHA256_DIGEST_SIZE];
    MtcTbsView fields;
    wc_Sha256 sha256;
    int ret;

    if (proof == NULL || entryHash == NULL ||
            (draftVersion != 3 && draftVersion != 5)) {
        return MTC_PARSE_BAD_ARGUMENT;
    }

    ret = MtcParseTbsCertificate(tbs, tbsLength, &fields);
    if (ret == MTC_PARSE_OK) {
        ret = MtcSha256Span(&fields.subjectPublicKeyInfo, spkiHash);
    }
    if (ret != MTC_PARSE_OK) {
        return ret;
    }

    ret = wc_InitSha256(&sha256);
    if (ret == 0) {
        ret = MtcSha256Update(&sha256, &domainSeparator,
            sizeof(domainSeparator));
        if (ret == 0 && draftVersion == 5) {
            extensionsLength[0] =
                (unsigned char)(proof->extensions.length >> 8);
            extensionsLength[1] =
                (unsigned char)(proof->extensions.length & 0xffU);
            ret = MtcSha256Update(&sha256, extensionsLength,
                sizeof(extensionsLength));
            if (ret == 0) {
                ret = MtcSha256Update(&sha256, proof->extensions.data,
                    proof->extensions.length);
            }
        }
        if (ret == 0) {
            ret = MtcSha256Update(&sha256, tbsCertEntry,
                sizeof(tbsCertEntry));
        }
        if (ret == 0) {
            ret = MtcSha256Update(&sha256, fields.version.data,
                fields.version.length);
        }
        if (ret == 0) {
            ret = MtcSha256Update(&sha256, fields.issuer.data,
                fields.issuer.length);
        }
        if (ret == 0) {
            ret = MtcSha256Update(&sha256, fields.validity.data,
                fields.validity.length);
        }
        if (ret == 0) {
            ret = MtcSha256Update(&sha256, fields.subject.data,
                fields.subject.length);
        }
        if (ret == 0) {
            ret = MtcSha256Update(&sha256, fields.publicKeyAlgorithm.data,
                fields.publicKeyAlgorithm.length);
        }
        if (ret == 0) {
            ret = MtcSha256Update(&sha256, spkiHashHeader,
                sizeof(spkiHashHeader));
        }
        if (ret == 0) {
            ret = MtcSha256Update(&sha256, spkiHash, sizeof(spkiHash));
        }
        if (ret == 0) {
            ret = MtcSha256Update(&sha256,
                fields.fieldsAfterSubjectPublicKeyInfo.data,
                fields.fieldsAfterSubjectPublicKeyInfo.length);
        }
        if (ret == 0) {
            ret = wc_Sha256Final(&sha256, entryHash);
        }
        wc_Sha256Free(&sha256);
    }

    return ret;
}

static const char* MtcParseErrorString(int error)
{
    switch (error) {
        case MTC_PARSE_BAD_ARGUMENT:
            return "bad argument";
        case MTC_PARSE_TRUNCATED:
            return "truncated vector";
        case MTC_PARSE_MALFORMED:
            return "malformed vector";
        case MTC_PARSE_TRAILING_DATA:
            return "trailing data";
        case MTC_PARSE_COSIGNER_ORDER:
            return "duplicate or incorrectly ordered cosigner ID";
        default:
            return "unknown parse error";
    }
}

static void MtcPrintHex(const unsigned char* data, size_t length)
{
    size_t i;

    for (i = 0; i < length; i++) {
        printf("%02x", data[i]);
    }
    putchar('\n');
}

static WOLFSSL_X509* MtcLoadCertificate(const char* fileName)
{
    WOLFSSL_X509* certificate;

    certificate = wolfSSL_X509_load_certificate_file(fileName,
        WOLFSSL_FILETYPE_PEM);
    if (certificate == NULL) {
        certificate = wolfSSL_X509_load_certificate_file(fileName,
            WOLFSSL_FILETYPE_ASN1);
    }

    return certificate;
}

static int MtcParseHashSize(const char* text, size_t* hashSize)
{
    size_t value = 0;
    const char* current;

    if (text == NULL || *text == '\0') {
        return 0;
    }

    for (current = text; *current != '\0'; current++) {
        size_t digit;

        if (*current < '0' || *current > '9') {
            return 0;
        }
        digit = (size_t)(*current - '0');
        if (value > (SIZE_MAX - digit) / 10U) {
            return 0;
        }
        value = value * 10U + digit;
    }
    if (value == 0U) {
        return 0;
    }

    *hashSize = value;
    return 1;
}

/* Draft-03 stores the entry index directly in serialNumber. Draft-05 stores
 * (log_number << 48) | index, so its entry index is the low 48 bits.
 */
static int MtcSerialToIndex(const unsigned char* serialNumber,
    size_t serialNumberLength, int draftVersion, uint64_t* index)
{
    uint64_t serial = 0;
    size_t offset = 0;

    if (serialNumber == NULL || serialNumberLength == 0U || index == NULL ||
            (draftVersion != 3 && draftVersion != 5)) {
        return 0;
    }

    while (offset < serialNumberLength && serialNumber[offset] == 0U) {
        offset++;
    }
    if (serialNumberLength - offset > sizeof(serial)) {
        return 0;
    }
    while (offset < serialNumberLength) {
        serial = (serial << 8) | serialNumber[offset++];
    }

    if (draftVersion == 5) {
        serial &= UINT64_C(0x0000ffffffffffff);
    }
    *index = serial;

    return 1;
}

static void MtcPrintUsage(const char* program)
{
    fprintf(stderr,
        "usage: %s [--brief] [--draft-03|--draft-05] [--hash-size bytes] "
        "certificate.pem|der\n", program);
}

int main(int argc, char** argv)
{
    WOLFSSL_X509* certificate = NULL;
    const unsigned char* tbsCertificate = NULL;
    unsigned char* signatureValue = NULL;
    unsigned char entryHash[WC_SHA256_DIGEST_SIZE];
    unsigned char serialNumber[EXTERNAL_SERIAL_SIZE];
    MtcProofView proof;
    const char* certificateFile = NULL;
    uint64_t index = 0;
    size_t hashSize = 0;
    int brief = 0;
    int hashSizeSet = 0;
    int draftVersion = 0;
    int tbsCertificateLength = 0;
    int serialNumberLength = (int)sizeof(serialNumber);
    int signatureValueLength = 0;
    int ret = EXIT_FAILURE;
    int parseRet;
    int draft05ParseRet = MTC_PARSE_OK;
    int argument;

    for (argument = 1; argument < argc; argument++) {
        const char* value = argv[argument];

        if (strcmp(value, "--brief") == 0) {
            brief = 1;
        }
        else if (strcmp(value, "--draft-03") == 0 ||
                strcmp(value, "--draft-05") == 0) {
            int selectedVersion = strcmp(value, "--draft-03") == 0 ? 3 : 5;

            if (draftVersion != 0 && draftVersion != selectedVersion) {
                fprintf(stderr, "only one draft version may be selected\n");
                return EXIT_FAILURE;
            }
            draftVersion = selectedVersion;
        }
        else if (strcmp(value, "--hash-size") == 0) {
            if (++argument >= argc || hashSizeSet ||
                    !MtcParseHashSize(argv[argument], &hashSize)) {
                fprintf(stderr, "invalid or missing --hash-size value\n");
                return EXIT_FAILURE;
            }
            hashSizeSet = 1;
        }
        else if (strncmp(value, "--hash-size=", 12) == 0) {
            if (hashSizeSet || !MtcParseHashSize(value + 12, &hashSize)) {
                fprintf(stderr, "invalid hash size: %s\n", value + 12);
                return EXIT_FAILURE;
            }
            hashSizeSet = 1;
        }
        else if (value[0] == '-') {
            fprintf(stderr, "unknown option: %s\n", value);
            MtcPrintUsage(argv[0]);
            return EXIT_FAILURE;
        }
        else if (certificateFile == NULL) {
            certificateFile = value;
        }
        else if (!hashSizeSet) {
            if (!MtcParseHashSize(value, &hashSize)) {
                fprintf(stderr, "invalid hash size: %s\n", value);
                return EXIT_FAILURE;
            }
            hashSizeSet = 1;
        }
        else {
            fprintf(stderr, "unexpected argument: %s\n", value);
            MtcPrintUsage(argv[0]);
            return EXIT_FAILURE;
        }
    }

    if (certificateFile == NULL) {
        MtcPrintUsage(argv[0]);
        return EXIT_FAILURE;
    }

    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        fprintf(stderr, "wolfSSL initialization failed\n");
        return EXIT_FAILURE;
    }

    certificate = MtcLoadCertificate(certificateFile);
    if (certificate == NULL) {
        fprintf(stderr, "unable to parse certificate: %s\n", certificateFile);
        goto cleanup;
    }

    if (wolfSSL_X509_get_signature_type(certificate) != CTC_MTC_PROOF) {
        fprintf(stderr, "certificate does not use id-alg-mtcProof\n");
        goto cleanup;
    }

    if (wolfSSL_X509_get_serial_number(certificate, serialNumber,
            &serialNumberLength) != WOLFSSL_SUCCESS ||
            serialNumberLength <= 0) {
        fprintf(stderr, "unable to read TBSCertificate.serialNumber\n");
        goto cleanup;
    }

    if (wolfSSL_X509_get_signature(certificate, NULL,
            &signatureValueLength) != WOLFSSL_SUCCESS ||
            signatureValueLength <= 0) {
        fprintf(stderr, "unable to read certificate signatureValue\n");
        goto cleanup;
    }

    signatureValue = (unsigned char*)malloc((size_t)signatureValueLength);
    if (signatureValue == NULL) {
        fprintf(stderr, "out of memory\n");
        goto cleanup;
    }

    if (wolfSSL_X509_get_signature(certificate, signatureValue,
            &signatureValueLength) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "unable to read certificate signatureValue\n");
        goto cleanup;
    }

    if (draftVersion == 3) {
        parseRet = MtcExtractInclusionProofDraft03(signatureValue,
            (size_t)signatureValueLength, &proof);
    }
    else {
        parseRet = MtcExtractInclusionProof(signatureValue,
            (size_t)signatureValueLength, &proof);
        draft05ParseRet = parseRet;
        if (parseRet == MTC_PARSE_OK) {
            draftVersion = 5;
        }
        else if (draftVersion == 0) {
            parseRet = MtcExtractInclusionProofDraft03(signatureValue,
                (size_t)signatureValueLength, &proof);
            if (parseRet == MTC_PARSE_OK) {
                draftVersion = 3;
            }
        }
    }
    if (parseRet != MTC_PARSE_OK) {
        if (draftVersion == 0) {
            fprintf(stderr,
                "invalid MTCProof (draft-05: %s; draft-03: %s)\n",
                MtcParseErrorString(draft05ParseRet),
                MtcParseErrorString(parseRet));
        }
        else {
            fprintf(stderr, "invalid draft-%02d MTCProof: %s\n",
                draftVersion, MtcParseErrorString(parseRet));
        }
        goto cleanup;
    }

    tbsCertificate = wolfSSL_X509_get_tbs(certificate,
        &tbsCertificateLength);
    if (tbsCertificate == NULL || tbsCertificateLength <= 0) {
        fprintf(stderr, "unable to read TBSCertificate DER\n");
        goto cleanup;
    }

    if (MtcCalculateEntryHash(tbsCertificate,
            (size_t)tbsCertificateLength, &proof, draftVersion,
            entryHash) != 0) {
        fprintf(stderr, "unable to calculate MerkleTreeCertEntry hash\n");
        goto cleanup;
    }

    if (hashSize != 0U && proof.inclusionProof.length % hashSize != 0U) {
        fprintf(stderr,
            "inclusion proof length is not a multiple of hash size %zu\n",
            hashSize);
        goto cleanup;
    }

    if (brief && !MtcSerialToIndex(serialNumber,
            (size_t)serialNumberLength, draftVersion, &index)) {
        fprintf(stderr, "unable to derive entry index from serial number\n");
        goto cleanup;
    }

    if (brief) {
        MtcPrintHex(entryHash, sizeof(entryHash));
        printf("%" PRIu64 "\n", index);
        printf("%" PRIu64 "\n", proof.start);
        printf("%" PRIu64 "\n", proof.end);
        if (hashSize == 0U) {
            if (proof.inclusionProof.length != 0U) {
                MtcPrintHex(proof.inclusionProof.data,
                    proof.inclusionProof.length);
            }
        }
        else {
            size_t i;

            for (i = 0; i < proof.inclusionProof.length / hashSize; i++) {
                MtcPrintHex(proof.inclusionProof.data + i * hashSize,
                    hashSize);
            }
        }
    }
    else {
        printf("encoding: draft-ietf-plants-merkle-tree-certs-%02d\n",
            draftVersion);
        printf("TBSCertificate.serialNumber: 0x");
        MtcPrintHex(serialNumber, (size_t)serialNumberLength);
        printf("SHA256(0x00 || MerkleTreeCertEntry): ");
        MtcPrintHex(entryHash, sizeof(entryHash));
        printf("subtree: [%" PRIu64 ", %" PRIu64 ")\n", proof.start,
            proof.end);
        printf("inclusion proof: %zu bytes\n", proof.inclusionProof.length);

        if (hashSize == 0U) {
            MtcPrintHex(proof.inclusionProof.data,
                proof.inclusionProof.length);
        }
        else {
            size_t i;

            for (i = 0; i < proof.inclusionProof.length / hashSize; i++) {
                printf("hash[%zu]: ", i);
                MtcPrintHex(proof.inclusionProof.data + i * hashSize,
                    hashSize);
            }
        }
    }

    ret = EXIT_SUCCESS;

cleanup:
    free(signatureValue);
    wolfSSL_X509_free(certificate);
    wolfSSL_Cleanup();
    return ret;
}
