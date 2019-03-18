/*
 * IPv6 Unicast Routing Pipeline (P4_16)
 *
 * Implements 128-bit routing table lookup, VRF routing domains, Hop Limit
 * validation, next-hop resolution, and ICMPv6 Time Exceeded generation.
 */

#ifndef _CHOCK_ROUTING_IPV6_ROUTING_P4_
#define _CHOCK_ROUTING_IPV6_ROUTING_P4_

#include "../arch/chock_arch.p4"
#include "../core/types.p4"
#include "../core/unified_headers.p4"
#include "../core/metadata.p4"

control ChockIpv6Routing(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    ChockCounter(32768, CounterType_t.PACKETS_AND_BYTES) ipv6_route_counters;

    action set_ipv6_next_hop(
        port_id_t   egress_port,
        ipv6_addr_t next_hop_ip,
        mac_addr_t  next_hop_mac,
        mac_addr_t  src_router_mac
    ) {
        ig_to_eg_md.egress_port = egress_port;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_UNICAST;
        user_meta.l3_meta.next_hop_ipv6 = next_hop_ip;
        user_meta.l3_meta.next_hop_mac = next_hop_mac;
        user_meta.l3_meta.source_router_mac = src_router_mac;
        user_meta.l3_meta.l3_route_hit = 1#1;

        hdr.ethernet.src_addr = src_router_mac;
        hdr.ethernet.dst_addr = next_hop_mac;
    }

    action drop_ipv6_unreachable() {
        ig_to_eg_md.drop_flag = 1#1;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_DROP;
        user_meta.l3_meta.send_icmp_unreachable = 1#1;
    }

    table ipv6_fib_lpm {
        key = {
            user_meta.l3_meta.vrf_id: exact;
            hdr.ipv6.dst_addr:        lpm;
        }
        actions = {
            set_ipv6_next_hop;
            drop_ipv6_unreachable;
        }
        size = 32768;
        default_action = drop_ipv6_unreachable();
    }

    apply {
        if (hdr.ipv6.isValid()) {
            if (hdr.ipv6.hop_limit <= 8#01) {
                user_meta.l3_meta.hop_limit_expired = 1#1;
                user_meta.l3_meta.send_icmp_time_exceeded = 1#1;
                ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_TO_CPU;
            } else {
                hdr.ipv6.hop_limit = hdr.ipv6.hop_limit - 8#01;
                ipv6_fib_lpm.apply();
                ipv6_route_counters.count((bit<32>)user_meta.l3_meta.vrf_id);
            }
        }
    }
}

#endif /* _CHOCK_ROUTING_IPV6_ROUTING_P4_ */
