/*
 * IPv4 Longest Prefix Match (LPM) Routing Pipeline (P4_16)
 *
 * Implements CIDR prefix table lookup, VRF routing domains, TTL validation,
 * next-hop MAC resolution, and ICMP time exceeded triggers.
 */

#ifndef _CHOCK_ROUTING_IPV4_LPM_P4_
#define _CHOCK_ROUTING_IPV4_LPM_P4_

#include "../arch/chock_arch.p4"
#include "../core/types.p4"
#include "../core/unified_headers.p4"
#include "../core/metadata.p4"

control ChockIpv4LpmRoute(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    ChockCounter(65536, CounterType_t.PACKETS_AND_BYTES) ipv4_route_counters;

    action set_next_hop_unicast(
        port_id_t   egress_port,
        ipv4_addr_t next_hop_ip,
        mac_addr_t  next_hop_mac,
        mac_addr_t  src_router_mac
    ) {
        ig_to_eg_md.egress_port = egress_port;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_UNICAST;
        user_meta.l3_meta.next_hop_ipv4 = next_hop_ip;
        user_meta.l3_meta.next_hop_mac = next_hop_mac;
        user_meta.l3_meta.source_router_mac = src_router_mac;
        user_meta.l3_meta.l3_route_hit = 1#1;

        hdr.ethernet.src_addr = src_router_mac;
        hdr.ethernet.dst_addr = next_hop_mac;
    }

    action set_ecmp_group(bit<8> ecmp_group_id) {
        user_meta.l3_meta.ecmp_group_id = ecmp_group_id;
        user_meta.l3_meta.l3_route_hit = 1#1;
    }

    action drop_unreachable() {
        ig_to_eg_md.drop_flag = 1#1;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_DROP;
        user_meta.l3_meta.send_icmp_unreachable = 1#1;
    }

    table ipv4_fib_lpm {
        key = {
            user_meta.l3_meta.vrf_id: exact;
            hdr.ipv4.dst_addr:        lpm;
        }
        actions = {
            set_next_hop_unicast;
            set_ecmp_group;
            drop_unreachable;
        }
        size = 65536;
        default_action = drop_unreachable();
    }

    apply {
        if (hdr.ipv4.isValid()) {
            /*
             * Check Time-to-Live (TTL)
             */
            if (hdr.ipv4.ttl <= 8#01) {
                user_meta.l3_meta.ttl_expired = 1#1;
                user_meta.l3_meta.send_icmp_time_exceeded = 1#1;
                ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_TO_CPU;
            } else {
                hdr.ipv4.ttl = hdr.ipv4.ttl - 8#01;
                ipv4_fib_lpm.apply();
                ipv4_route_counters.count((bit<32>)user_meta.l3_meta.vrf_id);
            }
        }
    }
}

#endif /* _CHOCK_ROUTING_IPV4_LPM_P4_ */
