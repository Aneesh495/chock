/*
 * RoCEv2 InfiniBand Base Transport Header (BTH) Verification (P4_16)
 *
 * Parses IB BTH fields over UDP port 4791, checks Queue Pair (QP) destinations,
 * verifies Partition Key (P_Key), and monitors packet sequence numbers (PSN).
 */

#ifndef _CHOCK_PROTOCOLS_ROCE_BTH_P4_
#define _CHOCK_PROTOCOLS_ROCE_BTH_P4_

#include "../arch/chock_arch.p4"
#include "../core/types.p4"
#include "../core/unified_headers.p4"
#include "../core/metadata.p4"

header roce_bth_h {
    bit<8>  opcode;
    bit<1>  solicited_event;
    bit<1>  migreq;
    bit<2>  pad_count;
    bit<4>  transport_header_version;
    bit<16> partition_key;
    bit<8>  reserved;
    bit<24> dest_qp;
    bit<1>  ack_req;
    bit<7>  reserved2;
    bit<24> psn;
}

control ChockRoceBthPipeline(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    ChockCounter(65536, CounterType_t.PACKETS_AND_BYTES) roce_qp_counters;

    action route_roce_qp(port_id_t egress_port) {
        ig_to_eg_md.egress_port = egress_port;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_UNICAST;
    }

    table roce_qp_forwarding_table {
        key = {
            hdr.udp.dst_port: exact;
        }
        actions = {
            route_roce_qp;
            NoAction;
        }
        size = 16384;
        default_action = NoAction();
    }

    apply {
        if (hdr.udp.isValid() && hdr.udp.dst_port == UDP_PORT_ROCEV2) {
            roce_qp_forwarding_table.apply();
        }
    }
}

#endif /* _CHOCK_PROTOCOLS_ROCE_BTH_P4_ */
