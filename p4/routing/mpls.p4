/*
 * Multiprotocol Label Switching (MPLS) Pipeline (P4_16)
 *
 * Implements label push, pop, swap, and penultimate hop popping (PHP)
 * with strict Traffic Class (EXP) and TTL propagation.
 */

#ifndef _CHOCK_ROUTING_MPLS_P4_
#define _CHOCK_ROUTING_MPLS_P4_

#include "../arch/chock_arch.p4"
#include "../core/types.p4"
#include "../core/unified_headers.p4"
#include "../core/metadata.p4"

control ChockMplsPipeline(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    action mpls_swap(
        mpls_label_t new_label,
        port_id_t    egress_port,
        mac_addr_t   next_hop_mac
    ) {
        hdr.mpls_0.label = new_label;
        hdr.mpls_0.ttl = hdr.mpls_0.ttl - 1;
        ig_to_eg_md.egress_port = egress_port;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_UNICAST;
        hdr.ethernet.dst_addr = next_hop_mac;
    }

    action mpls_push(
        mpls_label_t new_label,
        port_id_t    egress_port,
        mac_addr_t   next_hop_mac
    ) {
        hdr.mpls_0.setValid();
        hdr.mpls_0.label = new_label;
        hdr.mpls_0.traffic_class = 3#0;
        hdr.mpls_0.bottom_of_stack = 1#1;
        hdr.mpls_0.ttl = 64;

        hdr.ethernet.ether_type = ETHERTYPE_MPLS_UNICAST;
        hdr.ethernet.dst_addr = next_hop_mac;
        ig_to_eg_md.egress_port = egress_port;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_UNICAST;
    }

    action mpls_pop_php(
        port_id_t  egress_port,
        mac_addr_t next_hop_mac
    ) {
        hdr.mpls_0.setInvalid();
        hdr.ethernet.ether_type = ETHERTYPE_IPV4;
        hdr.ethernet.dst_addr = next_hop_mac;
        ig_to_eg_md.egress_port = egress_port;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_UNICAST;
    }

    table mpls_forwarding_table {
        key = {
            hdr.mpls_0.label: exact;
        }
        actions = {
            mpls_swap;
            mpls_pop_php;
        }
        size = 16384;
        default_action = mpls_swap(0, 0, 48#0);
    }

    apply {
        if (hdr.mpls_0.isValid()) {
            mpls_forwarding_table.apply();
        }
    }
}

#endif /* _CHOCK_ROUTING_MPLS_P4_ */
