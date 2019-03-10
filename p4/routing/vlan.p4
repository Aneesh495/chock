/*
 * 802.1Q and QinQ VLAN Classification and Tag Manipulation (P4_16)
 *
 * Implements ingress VLAN domain classification, access and trunk port validation,
 * native VLAN tagging, and egress tag push/pop/translation actions.
 */

#ifndef _CHOCK_ROUTING_VLAN_P4_
#define _CHOCK_ROUTING_VLAN_P4_

#include "../arch/chock_arch.p4"
#include "../core/types.p4"
#include "../core/unified_headers.p4"
#include "../core/metadata.p4"

control ChockVlanPipeline(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    action set_access_port_vlan(vlan_id_t default_vid) {
        user_meta.l2_meta.ingress_vlan_id = default_vid;
        hdr.vlan.setValid();
        hdr.vlan.pcp = 3#0;
        hdr.vlan.dei = 1#0;
        hdr.vlan.vid = default_vid;
        hdr.vlan.ether_type = hdr.ethernet.ether_type;
        hdr.ethernet.ether_type = ETHERTYPE_VLAN;
    }

    action validate_trunk_vlan(vlan_id_t allowed_vid) {
        user_meta.l2_meta.ingress_vlan_id = allowed_vid;
    }

    action translate_vlan_tag(vlan_id_t new_vid) {
        hdr.vlan.vid = new_vid;
        user_meta.l2_meta.egress_vlan_id = new_vid;
    }

    action push_provider_tag(vlan_id_t s_vid, bit<3> pcp) {
        hdr.provider_vlan.setValid();
        hdr.provider_vlan.pcp = pcp;
        hdr.provider_vlan.dei = 1#0;
        hdr.provider_vlan.vid = s_vid;
        hdr.provider_vlan.ether_type = hdr.ethernet.ether_type;
        hdr.ethernet.ether_type = ETHERTYPE_PROVIDER_VLAN;
    }

    action pop_vlan_tag() {
        if (hdr.vlan.isValid()) {
            hdr.ethernet.ether_type = hdr.vlan.ether_type;
            hdr.vlan.setInvalid();
        }
    }

    action drop_vlan_mismatch() {
        ig_to_eg_md.drop_flag = 1#1;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_DROP;
    }

    table ingress_port_vlan_table {
        key = {
            ig_intr_md.ingress_port:           exact;
            user_meta.l2_meta.ingress_vlan_id: ternary;
        }
        actions = {
            set_access_port_vlan;
            validate_trunk_vlan;
            push_provider_tag;
            drop_vlan_mismatch;
        }
        size = 4096;
        default_action = drop_vlan_mismatch();
    }

    table egress_vlan_translation_table {
        key = {
            ig_to_eg_md.egress_port:          exact;
            user_meta.l2_meta.ingress_vlan_id: exact;
        }
        actions = {
            translate_vlan_tag;
            pop_vlan_tag;
            NoAction;
        }
        size = 4096;
        default_action = NoAction();
    }

    apply {
        ingress_port_vlan_table.apply();
        egress_vlan_translation_table.apply();
    }
}

#endif /* _CHOCK_ROUTING_VLAN_P4_ */
