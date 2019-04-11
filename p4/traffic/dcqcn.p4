/*
 * RoCEv2 Data Center Quantized Congestion Notification (DCQCN) Pipeline (P4_16)
 *
 * Inspects InfiniBand BTH headers over RoCEv2, monitors queue thresholds,
 * marks ECN Congestion Experienced (CE) codepoints, and initiates Congestion
 * Notification Packet (CNP) generation.
 */

#ifndef _CHOCK_TRAFFIC_DCQCN_P4_
#define _CHOCK_TRAFFIC_DCQCN_P4_

#include "../arch/chock_arch.p4"
#include "../core/types.p4"
#include "../core/unified_headers.p4"
#include "../core/metadata.p4"

control ChockDcqcn(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_egress_intrinsic_metadata_t eg_intr_md
) {
    action mark_roce_ecn() {
        hdr.ipv4.ecn = ECN_CE;
        user_meta.traffic_meta.dcqcn_marked = 1#1;
    }

    action trigger_dcqcn_cnp() {
        user_meta.traffic_meta.dcqcn_cnp_generated = 1#1;
    }

    table dcqcn_threshold_table {
        key = {
            eg_intr_md.egress_port: exact;
        }
        actions = {
            mark_roce_ecn;
            trigger_dcqcn_cnp;
            NoAction;
        }
        size = 256;
        default_action = NoAction();
    }

    apply {
        if (hdr.udp.isValid() && hdr.udp.dst_port == UDP_PORT_ROCEV2) {
            /*
             * RoCEv2 DCQCN queue threshold: 250 packets
             */
            if (eg_intr_md.queue_depth_packets > 250) {
                dcqcn_threshold_table.apply();
            }
        }
    }
}

#endif /* _CHOCK_TRAFFIC_DCQCN_P4_ */
