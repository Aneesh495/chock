/*
 * NetPaxos In-Network Consensus Sequencer (P4_16)
 *
 * Implements hardware Paxos consensus sequencer in switch data plane.
 * Enforces monotonic round and sequence assignment for Phase 1B and Phase 2B
 * consensus messages before packets reach distributed coordinator nodes.
 */

#ifndef _CHOCK_ACCEL_NETPAXOS_P4_
#define _CHOCK_ACCEL_NETPAXOS_P4_

#include "../arch/chock_arch.p4"
#include "../core/types.p4"
#include "../core/unified_headers.p4"
#include "../core/metadata.p4"
#include "netpaxos_headers.p4"

control ChockNetPaxos(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    /* Highest allocated consensus sequence per instance */
    ChockRegister<bit<32>>(4096, 0) instance_highest_seq;
    ChockRegister<bit<16>>(4096, 0) instance_highest_round;

    action stamp_consensus_sequence(bit<32> inst_idx) {
        bit<32> cur_seq = instance_highest_seq.read(inst_idx);
        bit<32> next_seq = cur_seq + 1;
        instance_highest_seq.write(inst_idx, next_seq);

        hdr.netpaxos.sequence_num = next_seq;
        user_meta.accel_meta.netpaxos_assigned_sequence = next_seq;
        user_meta.accel_meta.netpaxos_sequence_stamped = 1#1;
    }

    action drop_stale_paxos_message() {
        ig_to_eg_md.drop_flag = 1#1;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_DROP;
    }

    apply {
        if (hdr.netpaxos.isValid()) {
            bit<32> inst_idx = hdr.netpaxos.instance_id & 32#00000FFF;
            bit<16> high_rnd = instance_highest_round.read(inst_idx);

            if (hdr.netpaxos.msg_type == NETPAXOS_PHASE2A) {
                if (hdr.netpaxos.round >= high_rnd) {
                    instance_highest_round.write(inst_idx, hdr.netpaxos.round);
                    stamp_consensus_sequence(inst_idx);
                } else {
                    drop_stale_paxos_message();
                }
            }
        }
    }
}

#endif /* _CHOCK_ACCEL_NETPAXOS_P4_ */
