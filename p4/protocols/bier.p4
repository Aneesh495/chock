/*
 * Bit Index Explicit Replication (BIER RFC 8279) Multicast Forwarding (P4_16)
 *
 * Implements tree-less multicast forwarding using bitstrings. Matches bitstrings
 * against Bit Forwarding Router (BFR) neighbor Bit-String Masks (BSM) and
 * replicates packets only to downstream interfaces with non-zero matching bits.
 */

#ifndef _CHOCK_PROTOCOLS_BIER_P4_
#define _CHOCK_PROTOCOLS_BIER_P4_

#include "../arch/chock_arch.p4"
#include "../core/types.p4"
#include "../core/unified_headers.p4"
#include "../core/metadata.p4"

header bier_h {
    bit<4>   bier_type;
    bit<4>   version;
    bit<4>   bsl; /* Bitstring Length: 64, 128, 256 */
    bit<20>  entropy;
    bit<6>   oam;
    bit<2>   reserved;
    bit<6>   dscp;
    bit<2>   proto;
    bit<16>  bfir_id;
    bit<64>  bitstring;
}

control ChockBierForwarding(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    action forward_bier_neighbor(
        port_id_t egress_port,
        bit<64>   neighbor_mask,
        mac_addr_t neighbor_mac
    ) {
        ig_to_eg_md.egress_port = egress_port;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_MULTICAST;
        hdr.ethernet.dst_addr = neighbor_mac;
    }

    table bier_bift_table {
        key = {
            ig_intr_md.ingress_port: exact;
        }
        actions = {
            forward_bier_neighbor;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    apply {
        bier_bift_table.apply();
    }
}

#endif /* _CHOCK_PROTOCOLS_BIER_P4_ */
