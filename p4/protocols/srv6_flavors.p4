/*
 * SRv6 Next-Hop Flavors: PSP, USP, and USD (P4_16)
 *
 * Implements standard SRv6 Segment Routing Flavors (RFC 8986 Section 4.1):
 * - PSP: Penultimate Segment Popping (pops SRH at penultimate node)
 * - USP: Ultimate Segment Popping (pops SRH at destination node)
 * - USD: Ultimate Segment Decapsulation (pops outer IPv6 header at destination)
 */

#ifndef _CHOCK_PROTOCOLS_SRV6_FLAVORS_P4_
#define _CHOCK_PROTOCOLS_SRV6_FLAVORS_P4_

#include "../arch/chock_arch.p4"
#include "../core/types.p4"
#include "../core/unified_headers.p4"
#include "../core/metadata.p4"

control ChockSrv6Flavors(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    action apply_psp_flavor() {
        if (hdr.srv6_srh.segments_left == 1) {
            /* Pop SRH header at penultimate segment */
            hdr.srv6_srh.setInvalid();
            hdr.srv6_seg0.setInvalid();
            hdr.srv6_seg1.setInvalid();
            hdr.srv6_seg2.setInvalid();
            hdr.srv6_seg3.setInvalid();
            hdr.ipv6.next_hdr = hdr.srv6_srh.next_hdr;
        }
    }

    action apply_usd_flavor(vrf_id_t inner_vrf) {
        if (hdr.srv6_srh.segments_left == 0) {
            /* Decapsulate full outer IPv6 header */
            hdr.ipv6.setInvalid();
            hdr.srv6_srh.setInvalid();
            hdr.srv6_seg0.setInvalid();
            user_meta.l3_meta.vrf_id = inner_vrf;
        }
    }

    table srv6_flavor_execution_table {
        key = {
            hdr.ipv6.dst_addr: exact;
        }
        actions = {
            apply_psp_flavor;
            apply_usd_flavor;
            NoAction;
        }
        size = 4096;
        default_action = NoAction();
    }

    apply {
        if (hdr.srv6_srh.isValid()) {
            srv6_flavor_execution_table.apply();
        }
    }
}

#endif /* _CHOCK_PROTOCOLS_SRV6_FLAVORS_P4_ */
