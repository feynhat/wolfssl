/* cosign.h
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 */

#ifndef WOLFSSL_MTC_COSIGN_H
#define WOLFSSL_MTC_COSIGN_H

#include <wolfssl/wolfcrypt/types.h>

/* Construct the TLS encoding of a draft-05 CosignedMessage.
 *
 * cosignerId and logId contain binary TrustAnchorID values without their
 * one-byte vector lengths. Their corresponding cosigner_name and log_origin
 * fields are encoded as "oid/1.3.6.1.4.1." followed by the dotted-decimal
 * representation of the ID.
 *
 * subtreeHashLen must be HASH_SIZE for the issuance log's hash algorithm. A
 * non-zero timestamp is only valid when start is zero; the caller is
 * responsible for ensuring end is the largest consistent tree observed.
 *
 * On input, *messageLen is the size of message. On success it is set to the
 * number of bytes written. Passing message as NULL sets *messageLen to the
 * required size and returns LENGTH_ONLY_E. A short output buffer returns
 * BUFFER_E and also reports the required size in *messageLen.
 */
int mtc_cosigned_message_create(byte* message, size_t* messageLen,
    const byte* cosignerId, size_t cosignerIdLen, word64 timestamp,
    const byte* logId, size_t logIdLen, word64 start, word64 end,
    const byte* subtreeHash, size_t subtreeHashLen);

#endif /* WOLFSSL_MTC_COSIGN_H */
