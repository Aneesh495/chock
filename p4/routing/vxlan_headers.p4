/*
 * Virtual Extensible LAN (VXLAN) Header Definitions (P4_16)
 *
 * Defines the VXLAN encapsulation header (RFC 7348) and Geneve header (RFC 8926).
 */

#ifndef _CHOCK_ROUTING_VXLAN_HEADERS_P4_
#define _CHOCK_ROUTING_VXLAN_HEADERS_P4_

#include "../core/types.p4"

/*
 * VXLAN Header (RFC 7348, 8 bytes)
 */
header vxlan_h {
    bit<1>  flags_reserved1;
    bit<1>  flags_reserved2;
    bit<1>  flags_reserved3;
    bit<1>  flags_i;
    bit<4>  flags_reserved4;
    bit<24> reserved;
    vni_t   vni;
    bit<8>  reserved2;
}

/*
 * Geneve Tunnel Header (RFC 8926, 8 bytes base)
 */
header geneve_h {
    bit<2>  version;
    bit<6>  opt_len;
    bit<1>  o_flag;
    bit<1>  c_flag;
    bit<6>  rsvd;
    bit<16> protocol_type;
    vni_t   vni;
    bit<8>  reserved;
}

#endif /* _CHOCK_ROUTING_VXLAN_HEADERS_P4_ */
