/*
 * Chock Edge Gateway Switch Target (P4_16)
 *
 * Optimized pipeline configuration for multi-tenant edge gateways:
 * SRv6 overlay, NAT64 translation, VXLAN termination, and TCAM security.
 */

#ifndef _CHOCK_EDGE_P4_
#define _CHOCK_EDGE_P4_

#include "../arch/chock_arch.p4"
#include "../core/types.p4"
#include "../core/unified_headers.p4"
#include "../core/metadata.p4"
#include "../core/parser.p4"
#include "../core/deparser.p4"
#include "../core/checksum.p4"

#include "../routing/srv6_encap.p4"
#include "../routing/srv6_vrf.p4"
#include "../routing/vxlan.p4"
#include "../routing/ipv4_lpm.p4"
#include "../routing/ipv6_routing.p4"
#include "../security/acl.p4"
#include "../security/nat64.p4"

control ChockEdgeIngress(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    out chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    ChockAcl()          acl_stage;
    ChockNat64()        nat64_stage;
    ChockVxlanPipeline() vxlan_stage;
    ChockSrv6VrfDecap() srv6_decap_stage;
    ChockSrv6Encap()    srv6_encap_stage;
    ChockIpv4LpmRoute() ipv4_route_stage;
    ChockIpv6Routing()  ipv6_route_stage;

    apply {
        acl_stage.apply(hdr, user_meta, ig_intr_md, ig_to_eg_md);
        if (ig_to_eg_md.drop_flag == 1#1) return;

        if (hdr.ipv6.isValid()) {
            nat64_stage.apply(hdr, user_meta, ig_intr_md, ig_to_eg_md);
        }

        if (hdr.vxlan.isValid()) {
            vxlan_stage.apply(hdr, user_meta, ig_intr_md, ig_to_eg_md);
        }

        if (hdr.srv6_srh.isValid()) {
            srv6_decap_stage.apply(hdr, user_meta, ig_intr_md, ig_to_eg_md);
        } else {
            srv6_encap_stage.apply(hdr, user_meta, ig_intr_md, ig_to_eg_md);
        }

        if (hdr.ipv4.isValid()) {
            ipv4_route_stage.apply(hdr, user_meta, ig_intr_md, ig_to_eg_md);
        } else if (hdr.ipv6.isValid()) {
            ipv6_route_stage.apply(hdr, user_meta, ig_intr_md, ig_to_eg_md);
        }
    }
}

control ChockEdgeTrafficManager(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md,
    out chock_egress_intrinsic_metadata_t eg_intr_md
) {
    apply {
        eg_intr_md.egress_port = ig_to_eg_md.egress_port;
        eg_intr_md.egress_physical_port = ig_to_eg_md.egress_port;
        eg_intr_md.egress_global_timestamp = 100000;
        eg_intr_md.enq_timestamp = 99000;
        eg_intr_md.queue_latency_ns = 1000;
        eg_intr_md.queue_depth_packets = 5;
        eg_intr_md.queue_depth_bytes = 7500;
        eg_intr_md.queue_id = ig_to_eg_md.queue_id;
        eg_intr_md.traffic_class = ig_to_eg_md.traffic_class;
        eg_intr_md.deflection_flag = 1#0;
    }
}

control ChockEdgeEgress(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_egress_intrinsic_metadata_t eg_intr_md
) {
    apply {}
}

ChockSwitch(
    ChockTopParser(),
    ChockTopVerifyChecksum(),
    ChockEdgeIngress(),
    ChockEdgeTrafficManager(),
    ChockEdgeEgress(),
    ChockTopComputeChecksum(),
    ChockTopDeparser()
) main;

#endif /* _CHOCK_EDGE_P4_ */
