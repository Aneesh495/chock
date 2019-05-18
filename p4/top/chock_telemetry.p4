/*
 * Chock Telemetry and Congestion Switch Target (P4_16)
 *
 * Dedicated pipeline configuration for spine/leaf telemetry fabrics:
 * In-Band Network Telemetry (INT v2.1), Postcards, Flowlets, DCQCN, and RED.
 */

#ifndef _CHOCK_TELEMETRY_SWITCH_P4_
#define _CHOCK_TELEMETRY_SWITCH_P4_

#include "../arch/chock_arch.p4"
#include "../core/types.p4"
#include "../core/unified_headers.p4"
#include "../core/metadata.p4"
#include "../core/parser.p4"
#include "../core/deparser.p4"
#include "../core/checksum.p4"

#include "../routing/ipv4_lpm.p4"
#include "../routing/ecmp.p4"
#include "../telemetry/int_source.p4"
#include "../telemetry/int_transit.p4"
#include "../telemetry/int_sink.p4"
#include "../telemetry/postcard.p4"
#include "../traffic/flowlet.p4"
#include "../traffic/dcqcn.p4"
#include "../traffic/red_ecn.p4"

control ChockTelemetryIngress(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    out chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    ChockIpv4LpmRoute()     ipv4_route_stage;
    ChockEcmpSelect()       ecmp_stage;
    ChockFlowletSwitching() flowlet_stage;
    ChockIntSource()        int_source_stage;
    ChockIntSink()          int_sink_stage;

    apply {
        if (hdr.ipv4.isValid()) {
            ipv4_route_stage.apply(hdr, user_meta, ig_intr_md, ig_to_eg_md);
            ecmp_stage.apply(hdr, user_meta, ig_intr_md, ig_to_eg_md);
            flowlet_stage.apply(hdr, user_meta, ig_intr_md, ig_to_eg_md);
        }

        int_source_stage.apply(hdr, user_meta, ig_intr_md, ig_to_eg_md);
        int_sink_stage.apply(hdr, user_meta, ig_intr_md, ig_to_eg_md);
    }
}

control ChockTelemetryTrafficManager(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md,
    out chock_egress_intrinsic_metadata_t eg_intr_md
) {
    apply {
        eg_intr_md.egress_port = ig_to_eg_md.egress_port;
        eg_intr_md.egress_physical_port = ig_to_eg_md.egress_port;
        eg_intr_md.egress_global_timestamp = 100000;
        eg_intr_md.enq_timestamp = 97000;
        eg_intr_md.queue_latency_ns = 3000;
        eg_intr_md.queue_depth_packets = 300;
        eg_intr_md.queue_depth_bytes = 450000;
        eg_intr_md.queue_id = ig_to_eg_md.queue_id;
        eg_intr_md.traffic_class = ig_to_eg_md.traffic_class;
        eg_intr_md.deflection_flag = 1#0;
    }
}

control ChockTelemetryEgress(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_egress_intrinsic_metadata_t eg_intr_md
) {
    ChockIntTransit()       int_transit_stage;
    ChockPostcardTelemetry() postcard_stage;
    ChockDcqcn()            dcqcn_stage;
    ChockRedEcn()           red_ecn_stage;

    apply {
        int_transit_stage.apply(hdr, user_meta, eg_intr_md);
        postcard_stage.apply(hdr, user_meta, eg_intr_md);
        dcqcn_stage.apply(hdr, user_meta, eg_intr_md);
        red_ecn_stage.apply(hdr, user_meta, eg_intr_md);
    }
}

ChockSwitch(
    ChockTopParser(),
    ChockTopVerifyChecksum(),
    ChockTelemetryIngress(),
    ChockTelemetryTrafficManager(),
    ChockTelemetryEgress(),
    ChockTopComputeChecksum(),
    ChockTopDeparser()
) main;

#endif /* _CHOCK_TELEMETRY_SWITCH_P4_ */
