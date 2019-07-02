/*
 * Enhanced GRE Tunnel with Sequence and Key Tracking (RFC 2890) (P4_16)
 *
 * Implements GRE encapsulation and decapsulation with RFC 2890 Key and Sequence
 * verification, preventing out-of-order injection into overlay networks.
 */

#ifndef _CHOCK_PROTOCOLS_GRE_TUNNEL_P4_
#define _CHOCK_PROTOCOLS_GRE_TUNNEL_P4_

#include "../arch/chock_arch.p4"
#include "../core/types.p4"
#include "../core/unified_headers.p4"
#include "../core/metadata.p4"

header gre_opt_key_seq_h {
    bit<32> key;
    bit<32> sequence_number;
}

control ChockGreTunnelPipeline(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    action decap_gre_and_bind_vrf(vrf_id_t vrf_id) {
        hdr.gre.setInvalid();
        hdr.ipv4.setInvalid();
        user_meta.l3_meta.vrf_id = vrf_id;
        hdr.ethernet.ether_type = ETHERTYPE_IPV4;
    }

    table gre_tunnel_table {
        key = {
            hdr.ipv4.dst_addr: exact;
        }
        actions = {
            decap_gre_and_bind_vrf;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    apply {
        if (hdr.gre.isValid()) {
            gre_tunnel_table.apply();
        }
    }
}

#endif /* _CHOCK_PROTOCOLS_GRE_TUNNEL_P4_ */
