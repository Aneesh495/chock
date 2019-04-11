/*
 * Postcard Telemetry (INT-XD) Event Notification Pipeline (P4_16)
 *
 * Generates autonomous out-of-band telemetry postcards when instantaneous
 * queue depths cross configured microburst thresholds.
 */

#ifndef _CHOCK_TELEMETRY_POSTCARD_P4_
#define _CHOCK_TELEMETRY_POSTCARD_P4_

#include "../arch/chock_arch.p4"
#include "../core/types.p4"
#include "../core/unified_headers.p4"
#include "../core/metadata.p4"
#include "int_headers.p4"

control ChockPostcardTelemetry(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_egress_intrinsic_metadata_t eg_intr_md
) {
    ChockRegister<bit<32>>(1024, 0) postcard_seq_reg;

    action emit_postcard_report(bit<32> switch_id, bit<4> drop_reason) {
        hdr.int_postcard.setValid();
        hdr.int_postcard.version = 4#1;
        hdr.int_postcard.drop_reason = drop_reason;

        bit<32> seq = postcard_seq_reg.read(0);
        postcard_seq_reg.write(0, seq + 1);
        hdr.int_postcard.sequence_number = (bit<8>)seq;

        hdr.int_postcard.postcard_flags = 16#0001;
        hdr.int_postcard.switch_id = switch_id;
        hdr.int_postcard.ingress_port = user_meta.l2_meta.l2_egress_port;
        hdr.int_postcard.egress_port = eg_intr_md.egress_port;
        hdr.int_postcard.reserved = 14#0;
        hdr.int_postcard.queue_depth = eg_intr_md.queue_depth_packets;
        hdr.int_postcard.event_timestamp = eg_intr_md.egress_global_timestamp;
    }

    table postcard_trigger_table {
        key = {
            eg_intr_md.egress_port: exact;
        }
        actions = {
            emit_postcard_report;
            NoAction;
        }
        size = 256;
        default_action = NoAction();
    }

    apply {
        /*
         * Trigger postcard on high queue occupancy (> 1000 packets)
         */
        if (eg_intr_md.queue_depth_packets > 1000) {
            postcard_trigger_table.apply();
        }
    }
}

#endif /* _CHOCK_TELEMETRY_POSTCARD_P4_ */
