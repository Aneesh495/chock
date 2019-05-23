/*
 * Chock Enterprise Campus Switch Target (P4_16)
 *
 * Dedicated pipeline configuration for enterprise campus deployments:
 * 802.1Q VLANs, MAC learning, IPv4/IPv6 dual-stack, MPLS WAN, and QoS policing.
 */

#ifndef _CHOCK_ENTERPRISE_SWITCH_P4_
#define _CHOCK_ENTERPRISE_SWITCH_P4_

#include "../arch/chock_arch.p4"
#include "../core/types.p4"
#include "../core/unified_headers.p4"
#include "../core/metadata.p4"
#include "../core/parser.p4"
#include "../core/deparser.p4"
#include "../core/checksum.p4"

#include "../routing/l2_switch.p4"
#include "../routing/vlan.p4"
#include "../routing/ipv4_lpm.p4"
#include "../routing/ipv6_routing.p4"
#include "../routing/mpls.p4"
#include "../traffic/token_bucket.p4"
#include "../security/acl.p4"

control ChockEnterpriseIngress(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    out chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    ChockAcl()                  acl_stage;
    ChockTokenBucketPolicer()   policer_stage;
    ChockVlanPipeline()         vlan_stage;
    ChockMplsPipeline()         mpls_stage;
    ChockIpv4LpmRoute()         ipv4_route_stage;
    ChockIpv6Routing()          ipv6_route_stage;
    ChockL2Switch()             l2_switch_stage;

    apply {
        acl_stage.apply(hdr, user_meta, ig_intr_md, ig_to_eg_md);
        if (ig_to_eg_md.drop_flag == 1#1) return;

        policer_stage.apply(hdr, user_meta, ig_intr_md, ig_to_eg_md);
        if (ig_to_eg_md.drop_flag == 1#1) return;

        vlan_stage.apply(hdr, user_meta, ig_intr_md, ig_to_eg_md);

        if (hdr.mpls_0.isValid()) {
            mpls_stage.apply(hdr, user_meta, ig_intr_md, ig_to_eg_md);
        } else if (hdr.ipv4.isValid()) {
            ipv4_route_stage.apply(hdr, user_meta, ig_intr_md, ig_to_eg_md);
        } else if (hdr.ipv6.isValid()) {
            ipv6_route_stage.apply(hdr, user_meta, ig_intr_md, ig_to_eg_md);
        } else {
            l2_switch_stage.apply(hdr, user_meta, ig_intr_md, ig_to_eg_md);
        }
    }
}

control ChockEnterpriseTrafficManager(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md,
    out chock_egress_intrinsic_metadata_t eg_intr_md
) {
    apply {
        eg_intr_md.egress_port = ig_to_eg_md.egress_port;
        eg_intr_md.egress_physical_port = ig_to_eg_md.egress_port;
        eg_intr_md.egress_global_timestamp = 100000;
        eg_intr_md.enq_timestamp = 98500;
        eg_intr_md.queue_latency_ns = 1500;
        eg_intr_md.queue_depth_packets = 10;
        eg_intr_md.queue_depth_bytes = 15000;
        eg_intr_md.queue_id = ig_to_eg_md.queue_id;
        eg_intr_md.traffic_class = ig_to_eg_md.traffic_class;
        eg_intr_md.deflection_flag = 1#0;
    }
}

control ChockEnterpriseEgress(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_egress_intrinsic_metadata_t eg_intr_md
) {
    apply {}
}

ChockSwitch(
    ChockTopParser(),
    ChockTopVerifyChecksum(),
    ChockEnterpriseIngress(),
    ChockEnterpriseTrafficManager(),
    ChockEnterpriseEgress(),
    ChockTopComputeChecksum(),
    ChockTopDeparser()
) main;

#endif /* _CHOCK_ENTERPRISE_SWITCH_P4_ */
