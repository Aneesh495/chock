/*
 * Equal-Cost Multi-Path (ECMP) Hashing and Path Selection (P4_16)
 *
 * Computes 5-tuple polynomial hash vectors and maps traffic onto active
 * link bundle members with resilient next-hop load distribution.
 */

#ifndef _CHOCK_ROUTING_ECMP_P4_
#define _CHOCK_ROUTING_ECMP_P4_

#include "../arch/chock_arch.p4"
#include "../core/types.p4"
#include "../core/unified_headers.p4"
#include "../core/metadata.p4"

control ChockEcmpSelect(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    ChockHash<bit<16>>(HashAlgorithm_t.HASH_CRC32) ecmp_hasher;

    struct ecmp_5tuple_ipv4_t {
        ipv4_addr_t src_ip;
        ipv4_addr_t dst_ip;
        bit<8>      proto;
        bit<16>     src_port;
        bit<16>     dst_port;
    }

    action set_ecmp_member_path(
        port_id_t  selected_port,
        mac_addr_t next_hop_mac,
        mac_addr_t src_router_mac
    ) {
        ig_to_eg_md.egress_port = selected_port;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_UNICAST;
        user_meta.l3_meta.next_hop_mac = next_hop_mac;
        user_meta.l3_meta.source_router_mac = src_router_mac;

        hdr.ethernet.src_addr = src_router_mac;
        hdr.ethernet.dst_addr = next_hop_mac;
    }

    table ecmp_group_table {
        key = {
            user_meta.l3_meta.ecmp_group_id:    exact;
            user_meta.l3_meta.ecmp_member_index: exact;
        }
        actions = {
            set_ecmp_member_path;
        }
        size = 1024;
        default_action = set_ecmp_member_path(0, 48#0, 48#0);
    }

    apply {
        if (user_meta.l3_meta.ecmp_group_id != 0) {
            ecmp_5tuple_ipv4_t tuple5;
            tuple5.src_ip = hdr.ipv4.src_addr;
            tuple5.dst_ip = hdr.ipv4.dst_addr;
            tuple5.proto = hdr.ipv4.protocol;
            tuple5.src_port = user_meta.parser_meta.l4_src_port;
            tuple5.dst_port = user_meta.parser_meta.l4_dst_port;

            bit<16> hash_val = ecmp_hasher.compute(tuple5);
            user_meta.l3_meta.ecmp_hash_val = hash_val;
            /* Modulo 4 for 4-way ECMP group */
            user_meta.l3_meta.ecmp_member_index = (bit<8>)(hash_val & 16#0003);

            ecmp_group_table.apply();
        }
    }
}

#endif /* _CHOCK_ROUTING_ECMP_P4_ */
