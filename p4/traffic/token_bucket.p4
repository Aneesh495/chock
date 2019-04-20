/*
 * Hierarchical Token Bucket Policer (trTCM RFC 2698) (P4_16)
 *
 * Implements Two-Rate Three-Color Marker (trTCM) policing:
 * Meters packets against Committed Information Rate (CIR), Committed Burst Size (CBS),
 * Peak Information Rate (PIR), and Peak Burst Size (PBS).
 */

#ifndef _CHOCK_TRAFFIC_TOKEN_BUCKET_P4_
#define _CHOCK_TRAFFIC_TOKEN_BUCKET_P4_

#include "../arch/chock_arch.p4"
#include "../core/types.p4"
#include "../core/unified_headers.p4"
#include "../core/metadata.p4"

control ChockTokenBucketPolicer(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    ChockMeter(4096) trtcm_meter;

    action apply_traffic_policing(bit<32> meter_idx) {
        MeterColor_t color = trtcm_meter.execute(meter_idx, (bit<32>)ig_intr_md.packet_length_bytes);
        user_meta.traffic_meta.meter_result_color = color;

        if (color == MeterColor_t.COLOR_RED) {
            ig_to_eg_md.drop_flag = 1#1;
            ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_DROP;
        } else if (color == MeterColor_t.COLOR_YELLOW) {
            /* Demote DSCP on yellow packets */
            hdr.ipv4.dscp = DSCP_AF12;
        }
    }

    table traffic_policer_table {
        key = {
            ig_intr_md.ingress_port:  exact;
            hdr.ipv4.dscp:            ternary;
        }
        actions = {
            apply_traffic_policing;
            NoAction;
        }
        size = 4096;
        default_action = NoAction();
    }

    apply {
        if (hdr.ipv4.isValid()) {
            traffic_policer_table.apply();
        }
    }
}

#endif /* _CHOCK_TRAFFIC_TOKEN_BUCKET_P4_ */
