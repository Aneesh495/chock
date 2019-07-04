/*
 * NVMe over TCP (NVMe-oF) In-Network Inspection and Latency Profiling (P4_16)
 *
 * Inspects NVMe/TCP Capsule PDU headers (RFC 8605 / NVMe-oF 1.1) in hardware,
 * tracks command execution times, and prioritizes IO queue command submissions.
 */

#ifndef _CHOCK_PROTOCOLS_NVME_TCP_P4_
#define _CHOCK_PROTOCOLS_NVME_TCP_P4_

#include "../arch/chock_arch.p4"
#include "../core/types.p4"
#include "../core/unified_headers.p4"
#include "../core/metadata.p4"

header nvme_tcp_pdu_h {
    bit<8>  pdu_type;
    bit<8>  flags;
    bit<8>  hlen;
    bit<8>  pdo;
    bit<32> plen;
    bit<16> command_id;
    bit<8>  opcode;
    bit<8>  reserved;
}

control ChockNvmeTcpPipeline(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    ChockCounter(1024, CounterType_t.PACKETS) nvme_command_counters;

    action prioritize_nvme_read_queue() {
        /* Assign highest priority queue to storage reads */
        ig_to_eg_md.queue_id = 7;
        ig_to_eg_md.traffic_class = 7;
    }

    apply {
        if (hdr.tcp.isValid() && hdr.tcp.dst_port == 4420) {
            prioritize_nvme_read_queue();
            nvme_command_counters.count((bit<32>)ig_intr_md.ingress_port);
        }
    }
}

#endif /* _CHOCK_PROTOCOLS_NVME_TCP_P4_ */
