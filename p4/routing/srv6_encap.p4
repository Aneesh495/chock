/*
 * Segment Routing over IPv6 (SRv6) T.Encap Ingress Encapsulation (P4_16)
 *
 * Encapsulates incoming IPv4 or IPv6 packets into an outer IPv6 header
 * with an attached Segment Routing Header (SRH) containing an ordered SID stack.
 */

#ifndef _CHOCK_ROUTING_SRV6_ENCAP_P4_
#define _CHOCK_ROUTING_SRV6_ENCAP_P4_

#include "../arch/chock_arch.p4"
#include "../core/types.p4"
#include "../core/unified_headers.p4"
#include "../core/metadata.p4"

control ChockSrv6Encap(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    action encap_srv6_policy_2hops(
        ipv6_addr_t outer_src_ip,
        ipv6_addr_t sid_hop0,
        ipv6_addr_t sid_hop1,
        port_id_t   egress_port
    ) {
        /*
         * Setup outer IPv6 Header
         */
        hdr.ipv6.setValid();
        hdr.ipv6.version = 4#6;
        hdr.ipv6.traffic_class = 8#00;
        hdr.ipv6.flow_label = 20#0;
        hdr.ipv6.payload_len = hdr.ipv4.total_len + 16#28;
        hdr.ipv6.next_hdr = IP_PROTO_IPV6_ROUTE;
        hdr.ipv6.hop_limit = 64;
        hdr.ipv6.src_addr = outer_src_ip;
        hdr.ipv6.dst_addr = sid_hop1;

        /*
         * Setup Segment Routing Header (SRH)
         */
        hdr.srv6_srh.setValid();
        hdr.srv6_srh.next_hdr = IP_PROTO_IPV4_ENCAP;
        hdr.srv6_srh.hdr_ext_len = 8#04;
        hdr.srv6_srh.routing_type = 8#04;
        hdr.srv6_srh.segments_left = 8#01;
        hdr.srv6_srh.last_entry = 8#01;
        hdr.srv6_srh.flags = 8#00;
        hdr.srv6_srh.tag = 16#0000;

        hdr.srv6_seg0.setValid();
        hdr.srv6_seg0.sid = sid_hop0;

        hdr.srv6_seg1.setValid();
        hdr.srv6_seg1.sid = sid_hop1;

        hdr.ethernet.ether_type = ETHERTYPE_IPV6;
        ig_to_eg_md.egress_port = egress_port;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_UNICAST;
    }

    table srv6_policy_table {
        key = {
            user_meta.l3_meta.vrf_id: exact;
            hdr.ipv4.dst_addr:        lpm;
        }
        actions = {
            encap_srv6_policy_2hops;
            NoAction;
        }
        size = 2048;
        default_action = NoAction();
    }

    apply {
        if (hdr.ipv4.isValid() && !hdr.srv6_srh.isValid()) {
            srv6_policy_table.apply();
        }
    }
}

#endif /* _CHOCK_ROUTING_SRV6_ENCAP_P4_ */
