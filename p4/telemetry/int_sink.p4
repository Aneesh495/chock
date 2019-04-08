/*
 * In-Band Network Telemetry (INT v2.1) Sink Pipeline (P4_16)
 *
 * Strips the telemetry headers from the incoming transit packet and generates
 * a cloned/mirrored telemetry report forwarded to the telemetry collector.
 */

#ifndef _CHOCK_TELEMETRY_INT_SINK_P4_
#define _CHOCK_TELEMETRY_INT_SINK_P4_

#include "../arch/chock_arch.p4"
#include "../core/types.p4"
#include "../core/unified_headers.p4"
#include "../core/metadata.p4"
#include "int_headers.p4"

control ChockIntSink(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    action strip_int_and_forward(port_id_t collector_port) {
        user_meta.int_meta.int_sink_node = 1#1;
        user_meta.int_meta.int_mirror_report = 1#1;

        hdr.int_shim.setInvalid();
        hdr.int_metadata_hdr.setInvalid();
        hdr.int_hop_switch_id.setInvalid();
        hdr.int_hop_ports.setInvalid();
        hdr.int_hop_latency.setInvalid();
        hdr.int_hop_queue_occupancy.setInvalid();
    }

    table int_sink_table {
        key = {
            hdr.ipv4.dst_addr: exact;
        }
        actions = {
            strip_int_and_forward;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    apply {
        if (hdr.int_shim.isValid()) {
            int_sink_table.apply();
        }
    }
}

#endif /* _CHOCK_TELEMETRY_INT_SINK_P4_ */
