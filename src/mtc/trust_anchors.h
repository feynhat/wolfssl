/* trust_anchors.h
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 */

#ifndef WOLFSSL_MTC_TRUST_ANCHORS_H
#define WOLFSSL_MTC_TRUST_ANCHORS_H

#include <wolfssl/wolfcrypt/types.h>

#ifdef WOLFSSL_MTC
    typedef struct TrustAnchorIDs {
        byte*  ids;
        word16 idsSz;
    } TrustAnchorIDs;
#endif

#endif /* WOLFSSL_MTC_TRUST_ANCHORS_H */
