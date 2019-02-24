/*
 * Multiprotocol Label Switching (MPLS) Header Definitions (P4_16)
 *
 * Defines the 32-bit MPLS label stack entry (RFC 3032).
 */

#ifndef _CHOCK_ROUTING_MPLS_HEADERS_P4_
#define _CHOCK_ROUTING_MPLS_HEADERS_P4_

#include "../core/types.p4"

/*
 * MPLS Label Stack Entry (32 bits / 4 bytes)
 */
header mpls_tag_h {
    mpls_label_t label;
    bit<3>       traffic_class;
    bit<1>       bottom_of_stack;
    bit<8>       ttl;
}

#endif /* _CHOCK_ROUTING_MPLS_HEADERS_P4_ */
