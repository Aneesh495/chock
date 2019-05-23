/*
 * Chock In-Network Compute Acceleration Switch Target (P4_16)
 *
 * Dedicated pipeline configuration for ultra-low latency compute clusters:
 * NetCache key-value caching, NetPaxos sequencer, and Market Feed arbitrator.
 */

#ifndef _CHOCK_ACCEL_SWITCH_P4_
#define _CHOCK_ACCEL_SWITCH_P4_

#include "../arch/chock_arch.p4"
#include "../core/types.p4"
#include "../core/unified_headers.p4"
#include "../core/metadata.p4"
#include "../core/parser.p4"
#include "../core/deparser.p4"
#include "../core/checksum.p4"

#include "../acceleration/netcache.p4"
#include "../acceleration/netcache_coherence.p4"
#include "../acceleration/netpaxos.p4"
#include "../acceleration/market_feed.p4"
#include "../routing/l2_switch.p4"

control ChockAccelIngress(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    out chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    ChockNetCache()             netcache_stage;
    ChockNetCacheCoherence()    netcache_coherence_stage;
    ChockNetPaxos()             netpaxos_stage;
    ChockMarketFeedArbitrator() market_feed_stage;
    ChockL2Switch()             l2_switch_stage;

    apply {
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

        l2_switch_stage.apply(hdr, user_meta, ig_intr_md, ig_to_eg_md);
    }
}

control ChockAccelTrafficManager(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md,
    out chock_egress_intrinsic_metadata_t eg_intr_md
) {
    apply {
        eg_intr_md.egress_port = ig_to_eg_md.egress_port;
        eg_intr_md.egress_physical_port = ig_to_eg_md.egress_port;
        eg_intr_md.egress_global_timestamp = 100000;
        eg_intr_md.enq_timestamp = 99900;
        eg_intr_md.queue_latency_ns = 100;
        eg_intr_md.queue_depth_packets = 1;
        eg_intr_md.queue_depth_bytes = 256;
        eg_intr_md.queue_id = ig_to_eg_md.queue_id;
        eg_intr_md.traffic_class = ig_to_eg_md.traffic_class;
        eg_intr_md.deflection_flag = 1#0;
    }
}

control ChockAccelEgress(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_egress_intrinsic_metadata_t eg_intr_md
) {
    apply {}
}

ChockSwitch(
    ChockTopParser(),
    ChockTopVerifyChecksum(),
    ChockAccelIngress(),
    ChockAccelTrafficManager(),
    ChockAccelEgress(),
    ChockTopComputeChecksum(),
    ChockTopDeparser()
) main;

#endif /* _CHOCK_ACCEL_SWITCH_P4_ */
