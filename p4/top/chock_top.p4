/*
 * Chock Top-Level Unified Programmable Switch (P4_16)
 *
 * Integrates all modular ingress and egress packet processing stages into a
 * single cohesive line-rate programmable data plane architecture.
 */

#ifndef _CHOCK_TOP_P4_
#define _CHOCK_TOP_P4_

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
#include "../routing/ecmp.p4"
#include "../routing/srv6_end.p4"
#include "../routing/srv6_end_x.p4"
#include "../routing/srv6_encap.p4"
#include "../routing/srv6_vrf.p4"
#include "../routing/vxlan.p4"
#include "../routing/mpls.p4"

#include "../telemetry/int_source.p4"
#include "../telemetry/int_transit.p4"
#include "../telemetry/int_sink.p4"
#include "../telemetry/postcard.p4"

#include "../traffic/flowlet.p4"
#include "../traffic/dcqcn.p4"
#include "../traffic/red_ecn.p4"
#include "../traffic/token_bucket.p4"

#include "../security/count_min_sketch.p4"
#include "../security/bloom_filter.p4"
#include "../security/acl.p4"
#include "../security/nat64.p4"

#include "../acceleration/netcache.p4"
#include "../acceleration/netcache_coherence.p4"
#include "../acceleration/netpaxos.p4"
#include "../acceleration/market_feed.p4"

/*
 * Unified Ingress Pipeline Control
 */
control ChockUnifiedIngress(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    out chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    ChockAcl()                  acl_stage;
    ChockBloomFilter()          bloom_filter_stage;
    ChockCountMinSketch()       count_min_sketch_stage;
    ChockTokenBucketPolicer()   token_bucket_stage;

    ChockNetCache()             netcache_stage;
    ChockNetCacheCoherence()    netcache_coherence_stage;
    ChockNetPaxos()             netpaxos_stage;
    ChockMarketFeedArbitrator() market_feed_stage;

    ChockVlanPipeline()         vlan_stage;
    ChockNat64()                nat64_stage;
    ChockVxlanPipeline()        vxlan_stage;
    ChockMplsPipeline()         mpls_stage;

    ChockSrv6VrfDecap()         srv6_decap_stage;
    ChockSrv6End()              srv6_end_stage;
    ChockSrv6EndX()             srv6_end_x_stage;
    ChockSrv6Encap()            srv6_encap_stage;

    ChockIpv4LpmRoute()         ipv4_route_stage;
    ChockIpv6Routing()          ipv6_route_stage;
    ChockEcmpSelect()           ecmp_stage;
    ChockFlowletSwitching()     flowlet_stage;
    ChockL2Switch()             l2_switch_stage;

    ChockIntSource()            int_source_stage;
    ChockIntSink()              int_sink_stage;

    apply {
        /*
         * Phase 1: Security Inspection & Traffic Metering
         */
        acl_stage.apply(hdr, user_meta, ig_intr_md, ig_to_eg_md);
        if (ig_to_eg_md.drop_flag == 1#1) return;

        bloom_filter_stage.apply(hdr, user_meta, ig_intr_md, ig_to_eg_md);
        if (ig_to_eg_md.drop_flag == 1#1) return;

        count_min_sketch_stage.apply(hdr, user_meta, ig_intr_md, ig_to_eg_md);
        token_bucket_stage.apply(hdr, user_meta, ig_intr_md, ig_to_eg_md);
        if (ig_to_eg_md.drop_flag == 1#1) return;

        /*
         * Phase 2: In-Network Compute Fast Paths
         */
        if (hdr.netcache.isValid()) {
            netcache_stage.apply(hdr, user_meta, ig_intr_md, ig_to_eg_md);
            netcache_coherence_stage.apply(hdr, user_meta, ig_intr_md, ig_to_eg_md);
            if (user_meta.accel_meta.netcache_cache_hit == 1#1) return;
        }

        if (hdr.netpaxos.isValid()) {
            netpaxos_stage.apply(hdr, user_meta, ig_intr_md, ig_to_eg_md);
            if (ig_to_eg_md.drop_flag == 1#1) return;
        }

        if (hdr.market_feed.isValid()) {
            market_feed_stage.apply(hdr, user_meta, ig_intr_md, ig_to_eg_md);
            if (ig_to_eg_md.drop_flag == 1#1) return;
        }

        /*
         * Phase 3: Ingress VLAN & Tunnel Classification
         */
        vlan_stage.apply(hdr, user_meta, ig_intr_md, ig_to_eg_md);
        if (hdr.vxlan.isValid()) {
            vxlan_stage.apply(hdr, user_meta, ig_intr_md, ig_to_eg_md);
        }
        if (hdr.ipv6.isValid()) {
            nat64_stage.apply(hdr, user_meta, ig_intr_md, ig_to_eg_md);
        }

        /*
         * Phase 4: SRv6 & MPLS Transport Routing
         */
        if (hdr.mpls_0.isValid()) {
            mpls_stage.apply(hdr, user_meta, ig_intr_md, ig_to_eg_md);
        } else if (hdr.srv6_srh.isValid()) {
            srv6_decap_stage.apply(hdr, user_meta, ig_intr_md, ig_to_eg_md);
            srv6_end_stage.apply(hdr, user_meta, ig_intr_md, ig_to_eg_md);
            srv6_end_x_stage.apply(hdr, user_meta, ig_intr_md, ig_to_eg_md);
        } else {
            srv6_encap_stage.apply(hdr, user_meta, ig_intr_md, ig_to_eg_md);
        }

        /*
         * Phase 5: L3 Routing, ECMP, Flowlet & L2 Forwarding
         */
        if (hdr.ipv4.isValid()) {
            ipv4_route_stage.apply(hdr, user_meta, ig_intr_md, ig_to_eg_md);
            ecmp_stage.apply(hdr, user_meta, ig_intr_md, ig_to_eg_md);
            flowlet_stage.apply(hdr, user_meta, ig_intr_md, ig_to_eg_md);
        } else if (hdr.ipv6.isValid()) {
            ipv6_route_stage.apply(hdr, user_meta, ig_intr_md, ig_to_eg_md);
            ecmp_stage.apply(hdr, user_meta, ig_intr_md, ig_to_eg_md);
        } else {
            l2_switch_stage.apply(hdr, user_meta, ig_intr_md, ig_to_eg_md);
        }

        /*
         * Phase 6: Telemetry Encapsulation / Decapsulation
         */
        int_source_stage.apply(hdr, user_meta, ig_intr_md, ig_to_eg_md);
        int_sink_stage.apply(hdr, user_meta, ig_intr_md, ig_to_eg_md);
    }
}

/*
 * Traffic Manager Simulation Model
 */
control ChockUnifiedTrafficManager(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md,
    out chock_egress_intrinsic_metadata_t eg_intr_md
) {
    apply {
        eg_intr_md.egress_port = ig_to_eg_md.egress_port;
        eg_intr_md.egress_physical_port = ig_to_eg_md.egress_port;
        eg_intr_md.egress_global_timestamp = 100000;
        eg_intr_md.enq_timestamp = 98000;
        eg_intr_md.queue_latency_ns = 2000;
        eg_intr_md.queue_depth_packets = 12;
        eg_intr_md.queue_depth_bytes = 18000;
        eg_intr_md.queue_id = ig_to_eg_md.queue_id;
        eg_intr_md.traffic_class = ig_to_eg_md.traffic_class;
        eg_intr_md.deflection_flag = 1#0;
    }
}

/*
 * Unified Egress Pipeline Control
 */
control ChockUnifiedEgress(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_egress_intrinsic_metadata_t eg_intr_md
) {
    ChockIntTransit()       int_transit_stage;
    ChockPostcardTelemetry() postcard_stage;
    ChockDcqcn()            dcqcn_stage;
    ChockRedEcn()           red_ecn_stage;

    apply {
        int_transit_stage.apply(hdr, user_meta, eg_intr_md);
        postcard_stage.apply(hdr, user_meta, eg_intr_md);
        dcqcn_stage.apply(hdr, user_meta, eg_intr_md);
        red_ecn_stage.apply(hdr, user_meta, eg_intr_md);
    }
}

/*
 * Complete Switch Architecture Instantiation
 */
ChockSwitch(
    ChockTopParser(),
    ChockTopVerifyChecksum(),
    ChockUnifiedIngress(),
    ChockUnifiedTrafficManager(),
    ChockUnifiedEgress(),
    ChockTopComputeChecksum(),
    ChockTopDeparser()
) main;

#endif /* _CHOCK_TOP_P4_ */
