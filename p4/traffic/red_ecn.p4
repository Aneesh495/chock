/*
 * Random Early Detection (RED) and ECN Marking Pipeline (P4_16)
 *
 * Implements exponential weighted moving average (EWMA) queue tracking and
 * linear probability ECN packet marking between min_th and max_th.
 */

#ifndef _CHOCK_TRAFFIC_RED_ECN_P4_
#define _CHOCK_TRAFFIC_RED_ECN_P4_

#include "../arch/chock_arch.p4"
#include "../core/types.p4"
#include "../core/unified_headers.p4"
#include "../core/metadata.p4"

control ChockRedEcn(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_egress_intrinsic_metadata_t eg_intr_md
) {
    ChockRegister<qdepth_t>(256, 0) ewma_queue_depth_reg;
    ChockRandom<bit<16>>() prng;

    action mark_ecn_congestion_experienced() {
        if (hdr.ipv4.isValid()) {
            if (hdr.ipv4.ecn != ECN_NOT_ECT) {
                hdr.ipv4.ecn = ECN_CE;
                user_meta.traffic_meta.ecn_congestion_experienced = 1#1;
            }
        }
    }

    action drop_congested_packet() {
        /* Tail drop fallback */
        hdr.ipv4.setInvalid();
        hdr.tcp.setInvalid();
        hdr.udp.setInvalid();
    }

    apply {
        if (hdr.ipv4.isValid()) {
            bit<32> port_idx = (bit<32>)eg_intr_md.egress_port;
            qdepth_t prev_ewma = ewma_queue_depth_reg.read(port_idx);

            /*
             * EWMA Queue Depth filter:
             * ewma = prev_ewma + (current_depth - prev_ewma) >> 4
             */
            qdepth_t curr_depth = eg_intr_md.queue_depth_packets;
            qdepth_t updated_ewma = prev_ewma + ((curr_depth - prev_ewma) >> 4);
            ewma_queue_depth_reg.write(port_idx, updated_ewma);

            user_meta.traffic_meta.ewma_queue_depth = updated_ewma;

            /*
             * RED parameters: min_th = 50, max_th = 200
             */
            if (updated_ewma >= 200) {
                mark_ecn_congestion_experienced();
            } else if (updated_ewma >= 50) {
                bit<16> rand_val = prng.get(0, 100);
                if (rand_val < 30) {
                    mark_ecn_congestion_experienced();
                }
            }
        }
    }
}

#endif /* _CHOCK_TRAFFIC_RED_ECN_P4_ */
