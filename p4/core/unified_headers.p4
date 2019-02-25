/*
 * Chock Unified Header Structure (P4_16)
 *
 * Encompasses all header declarations for top-level packet processing.
 */

#ifndef _CHOCK_CORE_UNIFIED_HEADERS_P4_
#define _CHOCK_CORE_UNIFIED_HEADERS_P4_

#include "types.p4"
#include "headers.p4"
#include "../telemetry/int_headers.p4"
#include "../routing/srv6_headers.p4"
#include "../routing/vxlan_headers.p4"
#include "../routing/mpls_headers.p4"
#include "../acceleration/netcache_headers.p4"
#include "../acceleration/netpaxos_headers.p4"
#include "../acceleration/market_feed_headers.p4"

struct headers_t {
    ethernet_h                 ethernet;
    provider_tag_h             provider_vlan;
    vlan_tag_h                 vlan;
    arp_h                      arp;
    mpls_tag_h                 mpls_0;
    mpls_tag_h                 mpls_1;
    mpls_tag_h                 mpls_2;
    ipv4_h                     ipv4;
    ipv6_h                     ipv6;
    srv6_srh_h                 srv6_srh;
    srv6_segment_0_h           srv6_seg0;
    srv6_segment_1_h           srv6_seg1;
    srv6_segment_2_h           srv6_seg2;
    srv6_segment_3_h           srv6_seg3;
    tcp_h                      tcp;
    udp_h                      udp;
    icmpv4_h                   icmpv4;
    icmpv6_h                   icmpv6;
    gre_h                      gre;
    nvgre_h                    nvgre;
    vxlan_h                    vxlan;
    geneve_h                   geneve;
    int_shim_h                 int_shim;
    int_metadata_hdr_h         int_metadata_hdr;
    int_hop_switch_id_h        int_hop_switch_id;
    int_hop_ports_h            int_hop_ports;
    int_hop_latency_h          int_hop_latency;
    int_hop_queue_occupancy_h  int_hop_queue_occupancy;
    int_postcard_h             int_postcard;
    netcache_h                 netcache;
    netpaxos_h                 netpaxos;
    market_feed_h              market_feed;
    inner_ethernet_h           inner_ethernet;
    inner_ipv4_h               inner_ipv4;
    inner_ipv6_h               inner_ipv6;
    inner_tcp_h                inner_tcp;
    inner_udp_h                inner_udp;
}

#endif /* _CHOCK_CORE_UNIFIED_HEADERS_P4_ */
