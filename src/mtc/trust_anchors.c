/* trust_anchors.c
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>
#include "src/mtc/trust_anchors.h"

#if !defined(WOLFSSL_MTC_TRUST_ANCHORS_INCLUDED)
    #ifndef WOLFSSL_IGNORE_FILE_WARN
        #warning trust_anchors.c does not need to be compiled separately
    #endif
#else

#if defined(WOLFSSL_TLS13) && defined(WOLFSSL_MTC)

/* Validate the contents of a RequestedTrustAnchorList or
 * AvailableTrustAnchorList after its two-byte vector length. */
static int TLSX_TrustAnchorIDs_Validate(const byte* ids, word16 idsSz,
    int allowEmpty)
{
    word16 offset = 0;

    if (idsSz == 0)
        return allowEmpty ? 0 : BUFFER_ERROR;
    if (ids == NULL)
        return BUFFER_ERROR;

    while (offset < idsSz) {
        byte idSz = ids[offset++];

        if (idSz == 0 || idSz > idsSz - offset)
            return BUFFER_ERROR;
        offset = (word16)(offset + idSz);
    }

    return 0;
}

static TrustAnchorIDs* TLSX_TrustAnchorIDs_New(const byte* ids, word16 idsSz,
    void* heap)
{
    TrustAnchorIDs* trustAnchors;

    if (idsSz > (word16)(WOLFSSL_MAX_16BIT - OPAQUE16_LEN) ||
            TLSX_TrustAnchorIDs_Validate(ids, idsSz, 1) != 0) {
        return NULL;
    }

    trustAnchors = (TrustAnchorIDs*)XMALLOC(sizeof(*trustAnchors), heap,
        DYNAMIC_TYPE_TLSX);
    if (trustAnchors == NULL)
        return NULL;

    XMEMSET(trustAnchors, 0, sizeof(*trustAnchors));
    if (idsSz > 0) {
        trustAnchors->ids = (byte*)XMALLOC(idsSz, heap, DYNAMIC_TYPE_TLSX);
        if (trustAnchors->ids == NULL) {
            XFREE(trustAnchors, heap, DYNAMIC_TYPE_TLSX);
            return NULL;
        }
        XMEMCPY(trustAnchors->ids, ids, idsSz);
        trustAnchors->idsSz = idsSz;
    }

    return trustAnchors;
}

static void TLSX_TrustAnchorIDs_Free(TrustAnchorIDs* trustAnchors, void* heap)
{
    if (trustAnchors != NULL) {
        XFREE(trustAnchors->ids, heap, DYNAMIC_TYPE_TLSX);
        XFREE(trustAnchors, heap, DYNAMIC_TYPE_TLSX);
    }
}

static word16 TLSX_TrustAnchorIDs_GetSize(const TrustAnchorIDs* trustAnchors)
{
    return (word16)(OPAQUE16_LEN + trustAnchors->idsSz);
}

static word16 TLSX_TrustAnchorIDs_Write(const TrustAnchorIDs* trustAnchors,
    byte* output)
{
    c16toa(trustAnchors->idsSz, output);
    if (trustAnchors->idsSz > 0) {
        XMEMCPY(output + OPAQUE16_LEN, trustAnchors->ids,
            trustAnchors->idsSz);
    }
    return (word16)(OPAQUE16_LEN + trustAnchors->idsSz);
}

/* Keep the peer's list separate from the local extension configuration. A
 * server may need the list after parsing ClientHello to select a certificate,
 * while the local extension list controls what this endpoint writes. */
static int TLSX_TrustAnchorIDs_StorePeer(WOLFSSL* ssl, const byte* ids,
    word16 idsSz)
{
    byte* copy = NULL;

    if (idsSz > 0) {
        copy = (byte*)XMALLOC(idsSz, ssl->heap, DYNAMIC_TYPE_TLSX);
        if (copy == NULL)
            return MEMORY_E;
        XMEMCPY(copy, ids, idsSz);
    }

    XFREE(ssl->peerTrustAnchorIds, ssl->heap, DYNAMIC_TYPE_TLSX);
    ssl->peerTrustAnchorIds = copy;
    ssl->peerTrustAnchorIdsSz = idsSz;
    ssl->peerTrustAnchorIdsPresent = 1;

    return 0;
}

static int TLSX_TrustAnchorIDs_Parse(WOLFSSL* ssl, const byte* input,
    word16 length, byte msgType)
{
    word16 idsSz;
    int allowEmpty;
    int ret;

    if (msgType == certificate)
        return length == 0 ? 0 : BUFFER_ERROR;
    if (msgType != client_hello && msgType != certificate_request &&
            msgType != encrypted_extensions) {
        return EXT_NOT_ALLOWED;
    }
    if (length < OPAQUE16_LEN)
        return BUFFER_ERROR;

    ato16(input, &idsSz);
    if (idsSz != length - OPAQUE16_LEN)
        return BUFFER_ERROR;

    /* Requested lists in ClientHello and CertificateRequest may be empty;
     * AvailableTrustAnchorList in EncryptedExtensions may not be empty. */
    allowEmpty = msgType != encrypted_extensions;
    ret = TLSX_TrustAnchorIDs_Validate(input + OPAQUE16_LEN, idsSz,
        allowEmpty);
    if (ret == 0)
        ret = TLSX_TrustAnchorIDs_StorePeer(ssl, input + OPAQUE16_LEN, idsSz);

    return ret;
}

static int TLSX_UseTrustAnchorIDs(TLSX** extensions, const byte* ids,
    word16 idsSz, void* heap)
{
    TLSX* extension;
    TrustAnchorIDs* trustAnchors;

    if (extensions == NULL || (idsSz > 0 && ids == NULL) ||
            idsSz > (word16)(WOLFSSL_MAX_16BIT - OPAQUE16_LEN) ||
            TLSX_TrustAnchorIDs_Validate(ids, idsSz, 1) != 0) {
        return BAD_FUNC_ARG;
    }

    trustAnchors = TLSX_TrustAnchorIDs_New(ids, idsSz, heap);
    if (trustAnchors == NULL)
        return MEMORY_E;

    extension = TLSX_Find(*extensions, TLSX_TRUST_ANCHORS);
    if (extension == NULL) {
        int ret = TLSX_Push(extensions, TLSX_TRUST_ANCHORS, trustAnchors,
            heap);

        if (ret != 0) {
            TLSX_TrustAnchorIDs_Free(trustAnchors, heap);
            return ret;
        }
    }
    else {
        TLSX_TrustAnchorIDs_Free((TrustAnchorIDs*)extension->data, heap);
        extension->data = trustAnchors;
    }

    return WOLFSSL_SUCCESS;
}

/* Set the draft-ietf-tls-trust-anchor-ids ClientHello extension. */
int wolfSSL_UseTrustAnchorIDs(WOLFSSL* ssl, const byte* ids, word16 idsSz)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    return TLSX_UseTrustAnchorIDs(&ssl->extensions, ids, idsSz, ssl->heap);
}

int wolfSSL_GetPeerTrustAnchorIDs(WOLFSSL* ssl, const byte** ids,
    word16* idsSz)
{
    if (ssl == NULL || ids == NULL || idsSz == NULL)
        return BAD_FUNC_ARG;

    *ids = NULL;
    *idsSz = 0;
    if (!ssl->peerTrustAnchorIdsPresent)
        return WOLFSSL_FAILURE;

    *ids = ssl->peerTrustAnchorIds;
    *idsSz = ssl->peerTrustAnchorIdsSz;
    return WOLFSSL_SUCCESS;
}

#define TAI_FREE(data, heap) \
    TLSX_TrustAnchorIDs_Free((TrustAnchorIDs*)(data), (heap))
#define TAI_GET_SIZE(data) \
    TLSX_TrustAnchorIDs_GetSize((const TrustAnchorIDs*)(data))
#define TAI_WRITE(data, output) \
    TLSX_TrustAnchorIDs_Write((const TrustAnchorIDs*)(data), (output))
#define TAI_PARSE      TLSX_TrustAnchorIDs_Parse

#endif /* WOLFSSL_TLS13 && WOLFSSL_MTC */

#endif /* WOLFSSL_MTC_TRUST_ANCHORS_INCLUDED */
