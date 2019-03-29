/*
 * Segment Routing over IPv6 (SRv6) End.X Cross-Connect Behavior (P4_16)
 *
 * Implements standard SRv6 End.X function (RFC 8986 Section 4.2):
 * Decrements Segments Left pointer, updates destination address, and directly
 * forwards packet to the assigned Layer 3 adjacency.
 */

#ifndef _CHOCK_ROUTING_SRV6_END_X_P4_
#define _CHOCK_ROUTING_SRV6_END_X_P4_

#include "../arch/chock_arch.p4"
#include "../core/types.p4"
#include "../core/unified_headers.p4"
#include "../core/metadata.p4"

control ChockSrv6EndX(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    action cross_connect_adjacency(
        port_id_t  target_port,
        mac_addr_t next_hop_mac,
        mac_addr_t router_mac
    ) {
        if (hdr.srv6_srh.segments_left > 0) {
            hdr.srv6_srh.segments_left = hdr.srv6_srh.segments_left - 1;
            user_meta.srv6_meta.segments_left = hdr.srv6_srh.segments_left;

            if (hdr.srv6_srh.segments_left == 0) {
                hdr.ipv6.dst_addr = hdr.srv6_seg0.sid;
            } else if (hdr.srv6_srh.segments_left == 1) {
                hdr.ipv6.dst_addr = hdr.srv6_seg1.sid;
            } else if (hdr.srv6_srh.segments_left == 2) {
                hdr.ipv6.dst_addr = hdr.srv6_seg2.sid;
            }
        }

        ig_to_eg_md.egress_port = target_port;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_UNICAST;

        hdr.ethernet.src_addr = router_mac;
        hdr.ethernet.dst_addr = next_hop_mac;
    }

    table srv6_end_x_table {
        key = {
            hdr.ipv6.dst_addr: exact;
        }
        actions = {
            cross_connect_adjacency;
        }
        size = 4096;
        default_action = cross_connect_adjacency(0, 48#0, 48#0);
    }

    apply {
        if (hdr.srv6_srh.isValid()) {
            srv6_end_x_table.apply();
        }
    }
}

#endif /* _CHOCK_ROUTING_SRV6_END_X_P4_ */
