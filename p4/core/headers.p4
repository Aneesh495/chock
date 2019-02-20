/*
 * Chock Protocol Header Definitions (P4_16)
 *
 * Defines wire format header structs for standard L2, L3, and L4 protocols,
 * encapsulation shims, and inner headers for overlays and tunnels.
 */

#ifndef _CHOCK_CORE_HEADERS_P4_
#define _CHOCK_CORE_HEADERS_P4_

#include "types.p4"

/*
 * IEEE 802.3 Ethernet MAC Header (14 bytes)
 */
header ethernet_h {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    bit<16>    ether_type;
}

/*
 * IEEE 802.1Q Customer VLAN Tag Header (4 bytes)
 */
header vlan_tag_h {
    bit<3>     pcp;
    bit<1>     dei;
    bit<12>    vid;
    bit<16>    ether_type;
}

/*
 * IEEE 802.1ad Service Provider Tag Header (QinQ outer tag, 4 bytes)
 */
header provider_tag_h {
    bit<3>     pcp;
    bit<1>     dei;
    bit<12>    vid;
    bit<16>    ether_type;
}

/*
 * Address Resolution Protocol (ARP) Header (28 bytes for IPv4 over Ethernet)
 */
header arp_h {
    bit<16>    hw_type;
    bit<16>    proto_type;
    bit<8>     hw_addr_len;
    bit<8>     proto_addr_len;
    bit<16>    opcode;
    mac_addr_t sender_hw_addr;
    ipv4_addr_t sender_proto_addr;
    mac_addr_t target_hw_addr;
    ipv4_addr_t target_proto_addr;
}

/*
 * Internet Protocol version 4 (IPv4) Base Header (20 bytes without options)
 */
header ipv4_h {
    bit<4>      version;
    bit<4>      ihl;
    bit<6>      dscp;
    bit<2>      ecn;
    bit<16>     total_len;
    bit<16>     identification;
    bit<3>      flags;
    bit<13>     frag_offset;
    bit<8>      ttl;
    bit<8>      protocol;
    bit<16>     hdr_checksum;
    ipv4_addr_t src_addr;
    ipv4_addr_t dst_addr;
}

/*
 * Internet Protocol version 6 (IPv6) Base Header (40 bytes)
 */
header ipv6_h {
    bit<4>       version;
    bit<8>       traffic_class;
    bit<20>      flow_label;
    bit<16>      payload_len;
    bit<8>       next_hdr;
    bit<8>       hop_limit;
    ipv6_addr_t  src_addr;
    ipv6_addr_t  dst_addr;
}

/*
 * IPv6 Hop-by-Hop Options Header (RFC 8200)
 */
header ipv6_hop_by_hop_h {
    bit<8>  next_hdr;
    bit<8>  hdr_ext_len;
    bit<48> reserved;
}

/*
 * IPv6 Routing Extension Header Base (RFC 8200)
 */
header ipv6_routing_base_h {
    bit<8>  next_hdr;
    bit<8>  hdr_ext_len;
    bit<8>  routing_type;
    bit<8>  segments_left;
}

/*
 * Internet Control Message Protocol v4 (ICMPv4) Header (8 bytes)
 */
header icmpv4_h {
    bit<8>  msg_type;
    bit<8>  msg_code;
    bit<16> checksum;
    bit<32> rest_of_header;
}

/*
 * Internet Control Message Protocol v6 (ICMPv6) Header (8 bytes)
 */
header icmpv6_h {
    bit<8>  msg_type;
    bit<8>  msg_code;
    bit<16> checksum;
    bit<32> rest_of_header;
}

/*
 * Transmission Control Protocol (TCP) Header (20 bytes without options)
 */
header tcp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4>  data_offset;
    bit<3>  reserved;
    bit<1>  ns;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window_size;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

/*
 * User Datagram Protocol (UDP) Header (8 bytes)
 */
header udp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> length;
    bit<16> checksum;
}

/*
 * Generic Routing Encapsulation (GRE) Header (RFC 2784 / RFC 2890, 4 bytes base)
 */
header gre_h {
    bit<1>  c_flag;
    bit<1>  r_flag;
    bit<1>  k_flag;
    bit<1>  s_flag;
    bit<9>  recurse;
    bit<3>  version;
    bit<16> protocol_type;
}

/*
 * Network Virtualization using Generic Routing Encapsulation (NVGRE) (RFC 7637)
 */
header nvgre_h {
    bit<1>  c_flag;
    bit<1>  r_flag;
    bit<1>  k_flag;
    bit<1>  s_flag;
    bit<9>  reserved;
    bit<3>  version;
    bit<16> protocol_type;
    vni_t   tni;
    bit<8>  flow_id;
}

/*
 * Inner Protocol Headers for Decapsulation and Overlay Processing
 */
header inner_ethernet_h {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    bit<16>    ether_type;
}

header inner_ipv4_h {
    bit<4>      version;
    bit<4>      ihl;
    bit<6>      dscp;
    bit<2>      ecn;
    bit<16>     total_len;
    bit<16>     identification;
    bit<3>      flags;
    bit<13>     frag_offset;
    bit<8>      ttl;
    bit<8>      protocol;
    bit<16>     hdr_checksum;
    ipv4_addr_t src_addr;
    ipv4_addr_t dst_addr;
}

header inner_ipv6_h {
    bit<4>       version;
    bit<8>       traffic_class;
    bit<20>      flow_label;
    bit<16>      payload_len;
    bit<8>       next_hdr;
    bit<8>       hop_limit;
    ipv6_addr_t  src_addr;
    ipv6_addr_t  dst_addr;
}

header inner_tcp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4>  data_offset;
    bit<3>  reserved;
    bit<1>  ns;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window_size;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header inner_udp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> length;
    bit<16> checksum;
}

#endif /* _CHOCK_CORE_HEADERS_P4_ */\n