/*
 * Segment Routing over IPv6 (SRv6) End.DT4 and End.DT6 Decapsulation (P4_16)
 *
 * Strips outer IPv6 header and SRH, binds the inner payload to a tenant VRF,
 * and passes the packet to inner routing lookup.
 */

#ifndef _CHOCK_ROUTING_SRV6_VRF_P4_
#define _CHOCK_ROUTING_SRV6_VRF_P4_

#include "../arch/chock_arch.p4"
#include "../core/types.p4"
#include "../core/unified_headers.p4"
#include "../core/metadata.p4"

control ChockSrv6VrfDecap(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    action end_dt4_decap(vrf_id_t tenant_vrf) {
        hdr.ipv6.setInvalid();
        hdr.srv6_srh.setInvalid();
        hdr.srv6_seg0.setInvalid();
        hdr.srv6_seg1.setInvalid();
        hdr.srv6_seg2.setInvalid();
        hdr.srv6_seg3.setInvalid();

        user_meta.l3_meta.vrf_id = tenant_vrf;
        hdr.ethernet.ether_type = ETHERTYPE_IPV4;
        user_meta.srv6_meta.srv6_decap_required = 1#1;
    }

    action end_dt6_decap(vrf_id_t tenant_vrf) {
        hdr.srv6_srh.setInvalid();
        hdr.srv6_seg0.setInvalid();
        hdr.srv6_seg1.setInvalid();
        hdr.srv6_seg2.setInvalid();
        hdr.srv6_seg3.setInvalid();

        user_meta.l3_meta.vrf_id = tenant_vrf;
        user_meta.srv6_meta.srv6_decap_required = 1#1;
    }

    table srv6_vrf_decap_table {
        key = {
            hdr.ipv6.dst_addr: exact;
        }
        actions = {
            end_dt4_decap;
            end_dt6_decap;
            NoAction;
        }
        size = 4096;
        default_action = NoAction();
    }

    apply {
        if (hdr.srv6_srh.isValid() && hdr.srv6_srh.segments_left == 0) {
            srv6_vrf_decap_table.apply();
        }
    }
}

#endif /* _CHOCK_ROUTING_SRV6_VRF_P4_ */
