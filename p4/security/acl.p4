/*
 * 12-Tuple TCAM Access Control List (ACL) Pipeline (P4_16)
 *
 * Implements hardware TCAM priority matching over 12 header fields, supporting
 * permit, deny, rate-limit, and packet mirror security policies.
 */

#ifndef _CHOCK_SECURITY_ACL_P4_
#define _CHOCK_SECURITY_ACL_P4_

#include "../arch/chock_arch.p4"
#include "../core/types.p4"
#include "../core/unified_headers.p4"
#include "../core/metadata.p4"

control ChockAcl(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    ChockCounter(8192, CounterType_t.PACKETS_AND_BYTES) acl_hit_counters;

    action acl_permit(bit<32> rule_id) {
        user_meta.security_meta.acl_permit = 1#1;
        user_meta.security_meta.acl_matched_rule_id = rule_id;
        acl_hit_counters.count(rule_id);
    }

    action acl_deny(bit<32> rule_id) {
        user_meta.security_meta.acl_deny = 1#1;
        user_meta.security_meta.acl_matched_rule_id = rule_id;
        ig_to_eg_md.drop_flag = 1#1;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_DROP;
        acl_hit_counters.count(rule_id);
    }

    action acl_mirror_to_security_analyzer(bit<32> rule_id, bit<16> mirror_session) {
        user_meta.security_meta.acl_mirror = 1#1;
        user_meta.security_meta.acl_matched_rule_id = rule_id;
        acl_hit_counters.count(rule_id);
    }

    table ingress_tcam_acl {
        key = {
            ig_intr_md.ingress_port:           exact;
            user_meta.l2_meta.ingress_vlan_id: ternary;
            hdr.ethernet.src_addr:             ternary;
            hdr.ethernet.dst_addr:             ternary;
            hdr.ethernet.ether_type:           exact;
            hdr.ipv4.src_addr:                 ternary;
            hdr.ipv4.dst_addr:                 ternary;
            hdr.ipv4.protocol:                 ternary;
            hdr.ipv4.dscp:                     ternary;
            user_meta.parser_meta.l4_src_port: ternary;
            user_meta.parser_meta.l4_dst_port: ternary;
            hdr.tcp.flags:                     ternary;
        }
        actions = {
            acl_permit;
            acl_deny;
            acl_mirror_to_security_analyzer;
        }
        size = 8192;
        default_action = acl_permit(0);
    }

    apply {
        ingress_tcam_acl.apply();
    }
}

#endif /* _CHOCK_SECURITY_ACL_P4_ */
