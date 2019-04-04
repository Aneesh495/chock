/*
 * In-Band Network Telemetry (INT v2.1) Transit Pipeline (P4_16)
 *
 * Populates local switch telemetry vector into the packet telemetry stack,
 * including switch ID, port IDs, queue occupancy, and hop latency.
 */

#ifndef _CHOCK_TELEMETRY_INT_TRANSIT_P4_
#define _CHOCK_TELEMETRY_INT_TRANSIT_P4_

#include "../arch/chock_arch.p4"
#include "../core/types.p4"
#include "../core/unified_headers.p4"
#include "../core/metadata.p4"
#include "int_headers.p4"

control ChockIntTransit(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_egress_intrinsic_metadata_t eg_intr_md
) {
    action stamp_transit_telemetry(bit<32> local_switch_id) {
        if (hdr.int_metadata_hdr.remaining_hop_cnt > 0) {
            hdr.int_metadata_hdr.remaining_hop_cnt = hdr.int_metadata_hdr.remaining_hop_cnt - 1;

            /*
             * Stamp Switch ID
             */
            if ((hdr.int_metadata_hdr.instruction_mask & INT_INS_SWITCH_ID) != 0) {
                hdr.int_hop_switch_id.setValid();
                hdr.int_hop_switch_id.switch_id = local_switch_id;
            }

            /*
             * Stamp Ingress and Egress Ports
             */
            if ((hdr.int_metadata_hdr.instruction_mask & INT_INS_INGRESS_EGRESS_PORT) != 0) {
                hdr.int_hop_ports.setValid();
                hdr.int_hop_ports.ingress_port = user_meta.l2_meta.l2_egress_port;
                hdr.int_hop_ports.pad0 = 7#0;
                hdr.int_hop_ports.egress_port = eg_intr_md.egress_port;
                hdr.int_hop_ports.pad1 = 7#0;
            }

            /*
             * Stamp Queue Occupancy and Latency
             */
            if ((hdr.int_metadata_hdr.instruction_mask & INT_INS_HOP_LATENCY) != 0) {
                hdr.int_hop_latency.setValid();
                hdr.int_hop_latency.hop_latency_ns = eg_intr_md.queue_latency_ns;
            }

            if ((hdr.int_metadata_hdr.instruction_mask & INT_INS_QUEUE_OCCUPANCY) != 0) {
                hdr.int_hop_queue_occupancy.setValid();
                hdr.int_hop_queue_occupancy.queue_id = eg_intr_md.queue_id;
                hdr.int_hop_queue_occupancy.queue_depth_packets = eg_intr_md.queue_depth_packets;
                hdr.int_hop_queue_occupancy.reserved = 5#0;
            }

            user_meta.int_meta.int_transit_node = 1#1;
        }
    }

    table int_transit_switch_config {
        actions = {
            stamp_transit_telemetry;
        }
        size = 1;
        default_action = stamp_transit_telemetry(32#00000001);
    }

    apply {
        if (hdr.int_metadata_hdr.isValid()) {
            int_transit_switch_config.apply();
        }
    }
}

#endif /* _CHOCK_TELEMETRY_INT_TRANSIT_P4_ */
