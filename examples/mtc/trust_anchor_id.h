/* Helpers shared by the Merkle Tree Certificate TLS examples. */

#ifndef WOLFSSL_EXAMPLES_MTC_TRUST_ANCHOR_ID_H
#define WOLFSSL_EXAMPLES_MTC_TRUST_ANCHOR_ID_H

/* Encode a dotted TrustAnchorID as one length-prefixed ASN.1 RELATIVE-OID
 * value, ready to place in a RequestedTrustAnchorList. */
static WC_INLINE int MtcEncodeTrustAnchorID(const char* oid, byte ids[256],
    word16* idsSz)
{
    word16 out = 1;

    if (*oid == '\0')
        return 0;
    while (*oid != '\0') {
        unsigned long arc = 0;
        byte encoded[5];
        int encodedSz = 0;

        if (*oid < '0' || *oid > '9')
            return 0;
        do {
            unsigned long digit = (unsigned long)(*oid++ - '0');

            if (arc > (0xffffffffUL - digit) / 10)
                return 0;
            arc = arc * 10 + digit;
        } while (*oid >= '0' && *oid <= '9');

        do {
            encoded[encodedSz++] = (byte)(arc & 0x7f);
            arc >>= 7;
        } while (arc != 0);
        if (out + encodedSz > 256)
            return 0;
        while (encodedSz-- > 0) {
            encoded[encodedSz] = (byte)(encoded[encodedSz] |
                (encodedSz != 0 ? 0x80 : 0));
            ids[out++] = encoded[encodedSz];
        }

        if (*oid == '.') {
            oid++;
            if (*oid == '\0')
                return 0;
        }
        else if (*oid != '\0')
            return 0;
    }

    ids[0] = (byte)(out - 1);
    *idsSz = out;
    return 1;
}

#endif /* WOLFSSL_EXAMPLES_MTC_TRUST_ANCHOR_ID_H */
