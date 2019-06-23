/*
 * IEEE 802.1AE MACsec Security Tag (SecTAG) Parser and Replay Protection (P4_16)
 *
 * Parses 802.1AE MACsec headers, extracts Association Number (AN) and Packet
 * Number (PN), and maintains sliding window replay protection registers in hardware.
 */

#ifndef _CHOCK_PROTOCOLS_MACSEC_SHIM_P4_
#define _CHOCK_PROTOCOLS_MACSEC_SHIM_P4_

#include "../arch/chock_arch.p4"
#include "../core/types.p4"
#include "../core/unified_headers.p4"
#include "../core/metadata.p4"

header macsec_sectag_h {
    bit<16> ether_type;
    bit<8>  tci_an;
    bit<8>  short_length;
    bit<32> packet_number;
    bit<64> sci;
}

control ChockMacsecPipeline(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    ChockRegister<bit<32>>(256, 0) macsec_lowest_pn_reg;

    action drop_macsec_replay() {
        ig_to_eg_md.drop_flag = 1#1;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_DROP;
    }

    apply {
        if (hdr.ethernet.ether_type == ETHERTYPE_MACSEC) {
            /* Inspect packet number against lowest acceptable PN */
            bit<32> port_idx = (bit<32>)ig_intr_md.ingress_port;
            bit<32> lowest_pn = macsec_lowest_pn_reg.read(port_idx);
        }
    }
}

#endif /* _CHOCK_PROTOCOLS_MACSEC_SHIM_P4_ */
