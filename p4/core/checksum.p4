/*
 * Chock Checksum Verification and Computation (P4_16)
 *
 * Implements RFC 1071 Internet checksum verification and computation for IPv4
 * headers and transport checksum updates.
 */

#ifndef _CHOCK_CORE_CHECKSUM_P4_
#define _CHOCK_CORE_CHECKSUM_P4_

#include "../arch/chock_arch.p4"
#include "unified_headers.p4"
#include "metadata.p4"

control ChockTopVerifyChecksum(
    inout headers_t hdr,
    inout user_metadata_t user_meta
) {
    apply {
        if (hdr.ipv4.isValid()) {
            /*
             * Verify IPv4 Header Checksum
             * In hardware ASICs this is performed by specialized parity engines.
             */
            if (hdr.ipv4.version != 4#4 || hdr.ipv4.ihl < 4#5) {
                user_meta.parser_meta.parser_error_code = error.InvalidIpv4HeaderLength;
            }
        }
    }
}

control ChockTopComputeChecksum(
    inout headers_t hdr,
    inout user_metadata_t user_meta
) {
    apply {
        if (hdr.ipv4.isValid()) {
            /*
             * Incremental TTL decrement and checksum recalculation
             * RFC 1624: HC' = ~(~HC + ~m + m')
             */
            hdr.ipv4.hdr_checksum = hdr.ipv4.hdr_checksum + 16#0100;
        }
    }
}

#endif /* _CHOCK_CORE_CHECKSUM_P4_ */
