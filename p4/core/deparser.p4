/*
 * Chock Multi-Protocol Header Deparser (P4_16)
 *
 * Reconstructs wire format egress packets by emitting valid headers in strict
 * network sequence from L2 encapsulation down to inner payloads.
 */

#ifndef _CHOCK_CORE_DEPARSER_P4_
#define _CHOCK_CORE_DEPARSER_P4_

#include "../arch/chock_arch.p4"
#include "unified_headers.p4"

control ChockTopDeparser(
    packet_out pkt,
    in headers_t hdr
) {
    apply {
        /*
         * Emit Outer L2 Headers
         */
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.provider_vlan);
        pkt.emit(hdr.vlan);
        pkt.emit(hdr.arp);

        /*
         * Emit Outer MPLS Label Stack
         */
        pkt.emit(hdr.mpls_0);
        pkt.emit(hdr.mpls_1);
        pkt.emit(hdr.mpls_2);

        /*
         * Emit Outer L3 Headers
         */
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.ipv6);

        /*
         * Emit SRv6 Segment Routing Extension Header & Segment List
         */
        pkt.emit(hdr.srv6_srh);
        pkt.emit(hdr.srv6_seg0);
        pkt.emit(hdr.srv6_seg1);
        pkt.emit(hdr.srv6_seg2);
        pkt.emit(hdr.srv6_seg3);

        /*
         * Emit L4 Transport Headers
         */
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.udp);
        pkt.emit(hdr.icmpv4);
        pkt.emit(hdr.icmpv6);

        /*
         * Emit Overlay and Tunnel Encapsulations
         */
        pkt.emit(hdr.gre);
        pkt.emit(hdr.nvgre);
        pkt.emit(hdr.vxlan);
        pkt.emit(hdr.geneve);

        /*
         * Emit In-Band Network Telemetry (INT v2.1) Stack
         */
        pkt.emit(hdr.int_shim);
        pkt.emit(hdr.int_metadata_hdr);
        pkt.emit(hdr.int_hop_switch_id);
        pkt.emit(hdr.int_hop_ports);
        pkt.emit(hdr.int_hop_latency);
        pkt.emit(hdr.int_hop_queue_occupancy);
        pkt.emit(hdr.int_postcard);

        /*
         * Emit In-Network Compute Acceleration Headers
         */
        pkt.emit(hdr.netcache);
        pkt.emit(hdr.netpaxos);
        pkt.emit(hdr.market_feed);

        /*
         * Emit Inner Headers for Overlay Forwarding
         */
        pkt.emit(hdr.inner_ethernet);
        pkt.emit(hdr.inner_ipv4);
        pkt.emit(hdr.inner_ipv6);
        pkt.emit(hdr.inner_tcp);
        pkt.emit(hdr.inner_udp);
    }
}

#endif /* _CHOCK_CORE_DEPARSER_P4_ */
