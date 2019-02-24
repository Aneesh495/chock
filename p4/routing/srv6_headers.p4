/*
 * Segment Routing over IPv6 (SRv6) Header Definitions (P4_16)
 *
 * Defines the Segment Routing Header (SRH, RFC 8754) and segment list entries.
 */

#ifndef _CHOCK_ROUTING_SRV6_HEADERS_P4_
#define _CHOCK_ROUTING_SRV6_HEADERS_P4_

#include "../core/types.p4"

/*
 * SRv6 Segment Routing Header (SRH) Fixed Base (8 bytes)
 */
header srv6_srh_h {
    bit<8>  next_hdr;
    bit<8>  hdr_ext_len;
    bit<8>  routing_type;
    bit<8>  segments_left;
    bit<8>  last_entry;
    bit<8>  flags;
    bit<16> tag;
}

/*
 * SRv6 128-bit Segment ID (SID) Stack Entries
 */
header srv6_segment_0_h { ipv6_addr_t sid; }
header srv6_segment_1_h { ipv6_addr_t sid; }
header srv6_segment_2_h { ipv6_addr_t sid; }
header srv6_segment_3_h { ipv6_addr_t sid; }
header srv6_segment_4_h { ipv6_addr_t sid; }
header srv6_segment_5_h { ipv6_addr_t sid; }
header srv6_segment_6_h { ipv6_addr_t sid; }
header srv6_segment_7_h { ipv6_addr_t sid; }

/*
 * SRv6 Endpoint Behaviors (RFC 8986)
 */
const bit<8> SRV6_BEHAVIOR_END         = 8#01;
const bit<8> SRV6_BEHAVIOR_END_X       = 8#02;
const bit<8> SRV6_BEHAVIOR_END_T       = 8#03;
const bit<8> SRV6_BEHAVIOR_END_DX2     = 8#04;
const bit<8> SRV6_BEHAVIOR_END_DX4     = 8#05;
const bit<8> SRV6_BEHAVIOR_END_DX6     = 8#06;
const bit<8> SRV6_BEHAVIOR_END_DT4     = 8#07;
const bit<8> SRV6_BEHAVIOR_END_DT6     = 8#08;
const bit<8> SRV6_BEHAVIOR_END_DT46    = 8#09;
const bit<8> SRV6_BEHAVIOR_END_B6_ENCAP = 8#0A;
const bit<8> SRV6_BEHAVIOR_END_B6_INSERT = 8#0B;

#endif /* _CHOCK_ROUTING_SRV6_HEADERS_P4_ */
