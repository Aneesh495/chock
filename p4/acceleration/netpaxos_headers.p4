/*
 * NetPaxos In-Network Consensus Protocol Header (P4_16)
 *
 * Defines hardware consensus messaging headers for in-network sequencer offload.
 */

#ifndef _CHOCK_ACCEL_NETPAXOS_HEADERS_P4_
#define _CHOCK_ACCEL_NETPAXOS_HEADERS_P4_

#include "../core/types.p4"

const bit<8> NETPAXOS_PHASE1A = 8#1A;
const bit<8> NETPAXOS_PHASE1B = 8#1B;
const bit<8> NETPAXOS_PHASE2A = 8#2A;
const bit<8> NETPAXOS_PHASE2B = 8#2B;

header netpaxos_h {
    bit<8>   msg_type;
    bit<8>   flags;
    bit<16>  round;
    bit<32>  instance_id;
    bit<32>  sequence_num;
    bit<64>  value_hash;
}

#endif /* _CHOCK_ACCEL_NETPAXOS_HEADERS_P4_ */
