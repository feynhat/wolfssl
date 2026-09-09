/* cosign.c
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

#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/types.h>

#include "src/mtc/cosign.h"

/* The terminating zero is part of the draft's 12-byte domain label. */
static const byte mtcCosignLabel[] = "subtree/v1\n";
static const byte mtcCosignOriginPrefix[] = "oid/1.3.6.1.4.1.";

static int mtc_cosign_add_size(size_t* total, size_t value)
{
    if (value > (size_t)-1 - *total)
        return BUFFER_E;
    *total += value;
    return 0;
}

/* Read one canonical base-128 TrustAnchorID component. */
static int mtc_cosign_read_id_component(const byte* id, size_t idLen,
    size_t* offset, const byte** component, size_t* componentLen)
{
    size_t start = *offset;
    byte current;

    do {
        if (*offset >= idLen)
            return BAD_FUNC_ARG;

        current = id[(*offset)++];
        if (*offset == start + 1U && current == 0x80U)
            return BAD_FUNC_ARG;
    } while ((current & 0x80U) != 0U);

    *component = id + start;
    *componentLen = *offset - start;
    return 0;
}

/* Convert an arbitrary-size base-128 OID component to decimal. */
static int mtc_cosign_component_to_decimal(byte* output, size_t* outputLen,
    const byte* component, size_t componentLen)
{
    byte digits[0xffU];
    size_t digitsLen = 1U;
    size_t i;

    digits[0] = 0;
    for (i = 0; i < componentLen; ++i) {
        word16 carry = (word16)(component[i] & 0x7fU);
        size_t j;

        for (j = 0; j < digitsLen; ++j) {
            word16 value = (word16)(digits[j] * 128U + carry);

            digits[j] = (byte)(value % 10U);
            carry = (word16)(value / 10U);
        }
        while (carry != 0U) {
            if (digitsLen == sizeof(digits))
                return BAD_FUNC_ARG;
            digits[digitsLen++] = (byte)(carry % 10U);
            carry = (word16)(carry / 10U);
        }
    }

    *outputLen = digitsLen;
    if (output != NULL) {
        for (i = 0; i < digitsLen; ++i)
            output[i] = (byte)('0' + digits[digitsLen - 1U - i]);
    }

    return 0;
}

/* Format a binary TrustAnchorID as the ASCII origin used by the draft. */
static int mtc_cosign_format_origin(byte* output, size_t* outputLen,
    const byte* id, size_t idLen)
{
    const size_t prefixLen = sizeof(mtcCosignOriginPrefix) - 1U;
    size_t offset = 0;
    size_t components = 0;
    size_t required = prefixLen;
    int ret = 0;

    if (outputLen == NULL || id == NULL || idLen == 0U || idLen > 0xffU)
        return BAD_FUNC_ARG;

    while (offset < idLen && ret == 0) {
        const byte* component;
        size_t componentLen;
        size_t decimalSize = 0;

        ret = mtc_cosign_read_id_component(id, idLen, &offset, &component,
            &componentLen);
        if (ret == 0) {
            ret = mtc_cosign_component_to_decimal(NULL, &decimalSize,
                component, componentLen);
        }
        if (ret != 0)
            break;
        if ((components != 0U &&
                mtc_cosign_add_size(&required, 1U) != 0) ||
                mtc_cosign_add_size(&required, decimalSize) != 0) {
            ret = BUFFER_E;
            break;
        }
        ++components;
    }

    if (ret == 0 && (components == 0U || required > 0xffU))
        ret = BAD_FUNC_ARG;
    if (ret != 0)
        return ret;

    *outputLen = required;
    if (output != NULL) {
        size_t written = prefixLen;

        XMEMCPY(output, mtcCosignOriginPrefix, prefixLen);
        offset = 0;
        components = 0;
        while (offset < idLen) {
            const byte* component;
            size_t componentLen;
            size_t decimalSize = 0;

            ret = mtc_cosign_read_id_component(id, idLen, &offset,
                &component, &componentLen);
            if (ret != 0)
                return ret;
            if (components++ != 0U)
                output[written++] = '.';
            ret = mtc_cosign_component_to_decimal(output + written,
                &decimalSize, component, componentLen);
            if (ret != 0)
                return ret;
            written += decimalSize;
        }
        if (written != required)
            return ASN_PARSE_E;
    }

    return 0;
}

static int mtc_cosign_valid_subtree(word64 start, word64 end)
{
    word64 size;
    word64 alignment;

    if (start >= end)
        return 0;
    if (start == 0U)
        return 1;

    size = end - start;
    if (size > ((word64)1U << 63))
        return 0;

    alignment = 1U;
    while (alignment < size)
        alignment <<= 1;

    return (start & (alignment - 1U)) == 0U;
}

static void mtc_cosign_write_u64(byte* output, word64 value)
{
    size_t i;

    for (i = 8U; i > 0U; --i) {
        output[i - 1U] = (byte)value;
        value >>= 8;
    }
}

int mtc_cosigned_message_create(byte* message, size_t* messageLen,
    const byte* cosignerId, size_t cosignerIdLen, word64 timestamp,
    const byte* logId, size_t logIdLen, word64 start, word64 end,
    const byte* subtreeHash, size_t subtreeHashLen)
{
    size_t cosignerNameLen = 0;
    size_t logOriginLen = 0;
    size_t required = sizeof(mtcCosignLabel) + 26U;
    size_t capacity;
    size_t offset = 0;
    size_t written;
    int ret;

    if (messageLen == NULL || subtreeHash == NULL || subtreeHashLen == 0U ||
            !mtc_cosign_valid_subtree(start, end) ||
            (timestamp != 0U && start != 0U)) {
        return BAD_FUNC_ARG;
    }

    ret = mtc_cosign_format_origin(NULL, &cosignerNameLen, cosignerId,
        cosignerIdLen);
    if (ret == 0) {
        ret = mtc_cosign_format_origin(NULL, &logOriginLen, logId,
            logIdLen);
    }
    if (ret != 0)
        return ret;

    if (mtc_cosign_add_size(&required, cosignerNameLen) != 0 ||
            mtc_cosign_add_size(&required, logOriginLen) != 0 ||
            mtc_cosign_add_size(&required, subtreeHashLen) != 0) {
        return BUFFER_E;
    }

    capacity = message == NULL ? 0U : *messageLen;
    *messageLen = required;
    if (message == NULL)
        return LENGTH_ONLY_E;
    if (capacity < required)
        return BUFFER_E;

    XMEMCPY(message + offset, mtcCosignLabel, sizeof(mtcCosignLabel));
    offset += sizeof(mtcCosignLabel);

    message[offset++] = (byte)cosignerNameLen;
    written = cosignerNameLen;
    ret = mtc_cosign_format_origin(message + offset, &written, cosignerId,
        cosignerIdLen);
    if (ret != 0)
        return ret;
    offset += written;

    mtc_cosign_write_u64(message + offset, timestamp);
    offset += 8U;

    message[offset++] = (byte)logOriginLen;
    written = logOriginLen;
    ret = mtc_cosign_format_origin(message + offset, &written, logId,
        logIdLen);
    if (ret != 0)
        return ret;
    offset += written;

    mtc_cosign_write_u64(message + offset, start);
    offset += 8U;
    mtc_cosign_write_u64(message + offset, end);
    offset += 8U;

    XMEMCPY(message + offset, subtreeHash, subtreeHashLen);
    offset += subtreeHashLen;

    if (offset != required)
        return ASN_PARSE_E;

    return 0;
}
