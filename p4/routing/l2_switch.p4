/*
 * Layer 2 Ethernet Switching and Bridging Pipeline (P4_16)
 *
 * Implements standard IEEE 802.1D MAC forwarding table, MAC learning digest
 * generation, split-horizon egress filtering, and multicast/broadcast flooding.
 */

#ifndef _CHOCK_ROUTING_L2_SWITCH_P4_
#define _CHOCK_ROUTING_L2_SWITCH_P4_

#include "../arch/chock_arch.p4"
#include "../core/types.p4"
#include "../core/unified_headers.p4"
#include "../core/metadata.p4"

control ChockL2Switch(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    /*
     * Learning Digest Message Structure
     */
    struct mac_learn_digest_t {
        mac_addr_t src_mac;
        vlan_id_t  vlan_id;
        port_id_t  ingress_port;
    }

    ChockDigest<mac_learn_digest_t>() mac_learn_digest;
    ChockCounter(4096, CounterType_t.PACKETS_AND_BYTES) l2_port_counters;

    action set_l2_unicast_egress(port_id_t egress_port) {
        ig_to_eg_md.egress_port = egress_port;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_UNICAST;
        user_meta.l2_meta.l2_egress_port = egress_port;
        user_meta.l2_meta.l2_lookup_hit = 1#1;
    }

    action flood_in_vlan(bit<16> multicast_group_id) {
        ig_to_eg_md.multicast_group = multicast_group_id;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_MULTICAST;
        user_meta.l2_meta.is_broadcast = 1#1;
    }

    action drop_l2(bit<8> drop_reason) {
        ig_to_eg_md.drop_flag = 1#1;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_DROP;
        user_meta.l2_meta.split_horizon_drop = 1#1;
    }

    table mac_forwarding_table {
        key = {
            user_meta.l2_meta.ingress_vlan_id: exact;
            hdr.ethernet.dst_addr:             exact;
        }
        actions = {
            set_l2_unicast_egress;
            flood_in_vlan;
            drop_l2;
        }
        size = 16384;
        default_action = flood_in_vlan(16#0001);
    }

    table mac_source_learning_table {
        key = {
            user_meta.l2_meta.ingress_vlan_id: exact;
            hdr.ethernet.src_addr:             exact;
        }
        actions = {
            NoAction;
        }
        size = 16384;
        default_action = NoAction();
    }

    apply {
        if (hdr.ethernet.isValid()) {
            /*
             * Source MAC Learning Check
             */
            if (!mac_source_learning_table.apply().hit) {
                mac_learn_digest_t msg;
                msg.src_mac = hdr.ethernet.src_addr;
                msg.vlan_id = user_meta.l2_meta.ingress_vlan_id;
                msg.ingress_port = ig_intr_md.ingress_port;
                mac_learn_digest.pack_and_send(msg);
                user_meta.l2_meta.mac_learn_required = 1#1;
            }

            /*
             * Check for Broadcast / Multicast Destination
             */
            if (hdr.ethernet.dst_addr[40:40] == 1#1) {
                flood_in_vlan(16#0001);
            } else {
                mac_forwarding_table.apply();
            }

            /*
             * Split-Horizon Ingress/Egress Port Check
             */
            if (ig_to_eg_md.egress_port == ig_intr_md.ingress_port &&
                ig_to_eg_md.decision == ForwardingDecision_t.FORWARD_UNICAST) {
                drop_l2(8#01);
            }

            l2_port_counters.count((bit<32>)ig_intr_md.ingress_port);
        }
    }
}

#endif /* _CHOCK_ROUTING_L2_SWITCH_P4_ */
