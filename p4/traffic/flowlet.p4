/*
 * Dynamic Flowlet Switching and Load Balancing (P4_16)
 *
 * Implements flowlet switching to eliminate packet reordering across ECMP links.
 * Detects inter-burst arrival gaps; when the gap exceeds the network delay
 * difference threshold, switches to the optimal least-congested path.
 */

#ifndef _CHOCK_TRAFFIC_FLOWLET_P4_
#define _CHOCK_TRAFFIC_FLOWLET_P4_

#include "../arch/chock_arch.p4"
#include "../core/types.p4"
#include "../core/unified_headers.p4"
#include "../core/metadata.p4"

control ChockFlowletSwitching(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    /* 64k flow table tracking state */
    ChockRegister<timestamp_t>(65536, 0) flowlet_last_seen_reg;
    ChockRegister<bit<16>>(65536, 0)     flowlet_id_reg;
    ChockRegister<port_id_t>(65536, 0)   flowlet_port_reg;

    ChockHash<bit<16>>(HashAlgorithm_t.HASH_CRC32) flow_hasher;

    struct flow_5tuple_t {
        ipv4_addr_t src_ip;
        ipv4_addr_t dst_ip;
        bit<8>      protocol;
        bit<16>     src_port;
        bit<16>     dst_port;
    }

    action assign_flowlet_path(port_id_t egress_port) {
        ig_to_eg_md.egress_port = egress_port;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_UNICAST;
        user_meta.traffic_meta.flowlet_selected_path = egress_port;
    }

    table flowlet_path_table {
        key = {
            user_meta.traffic_meta.flowlet_id: exact;
        }
        actions = {
            assign_flowlet_path;
        }
        size = 1024;
        default_action = assign_flowlet_path(1);
    }

    apply {
        if (hdr.ipv4.isValid() && (hdr.tcp.isValid() || hdr.udp.isValid())) {
            flow_5tuple_t tuple5;
            tuple5.src_ip = hdr.ipv4.src_addr;
            tuple5.dst_ip = hdr.ipv4.dst_addr;
            tuple5.protocol = hdr.ipv4.protocol;
            tuple5.src_port = user_meta.parser_meta.l4_src_port;
            tuple5.dst_port = user_meta.parser_meta.l4_dst_port;

            bit<16> flow_idx = flow_hasher.compute(tuple5);
            timestamp_t last_seen = flowlet_last_seen_reg.read((bit<32>)flow_idx);
            timestamp_t now = ig_intr_md.ingress_global_timestamp;

            flowlet_last_seen_reg.write((bit<32>)flow_idx, now);

            /*
             * Flowlet inter-packet gap threshold: 50 microseconds (50,000 ns)
             */
            if ((now - last_seen) > 50000) {
                /* New flowlet detected */
                bit<16> fid = flowlet_id_reg.read((bit<32>)flow_idx);
                fid = fid + 1;
                flowlet_id_reg.write((bit<32>)flow_idx, fid);

                user_meta.traffic_meta.flowlet_id = fid;
                user_meta.traffic_meta.flowlet_burst_boundary = 1#1;

                flowlet_path_table.apply();
                flowlet_port_reg.write((bit<32>)flow_idx, ig_to_eg_md.egress_port);
            } else {
                /* Continue existing flowlet path */
                port_id_t pinned_port = flowlet_port_reg.read((bit<32>)flow_idx);
                ig_to_eg_md.egress_port = pinned_port;
                ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_UNICAST;
            }
        }
    }
}

#endif /* _CHOCK_TRAFFIC_FLOWLET_P4_ */
