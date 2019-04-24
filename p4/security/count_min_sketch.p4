/*
 * 4-Stage Count-Min Sketch for Line-Rate Heavy Hitter Detection (P4_16)
 *
 * Implements a 4-row 65,536-column Count-Min Sketch using 4 independent polynomial
 * hash functions. Updates cell counters on each packet and flags elephant flows
 * crossing the heavy hitter threshold.
 */

#ifndef _CHOCK_SECURITY_COUNT_MIN_SKETCH_P4_
#define _CHOCK_SECURITY_COUNT_MIN_SKETCH_P4_

#include "../arch/chock_arch.p4"
#include "../core/types.p4"
#include "../core/unified_headers.p4"
#include "../core/metadata.p4"

control ChockCountMinSketch(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    /* 4 independent register arrays of 65,536 entries */
    ChockRegister<bit<32>>(65536, 0) sketch_row_0;
    ChockRegister<bit<32>>(65536, 0) sketch_row_1;
    ChockRegister<bit<32>>(65536, 0) sketch_row_2;
    ChockRegister<bit<32>>(65536, 0) sketch_row_3;

    ChockHash<bit<16>>(HashAlgorithm_t.HASH_POLYNOMIAL_STAGE0) hash_stage_0;
    ChockHash<bit<16>>(HashAlgorithm_t.HASH_POLYNOMIAL_STAGE1) hash_stage_1;
    ChockHash<bit<16>>(HashAlgorithm_t.HASH_POLYNOMIAL_STAGE2) hash_stage_2;
    ChockHash<bit<16>>(HashAlgorithm_t.HASH_POLYNOMIAL_STAGE3) hash_stage_3;

    struct flow_key_t {
        ipv4_addr_t src_ip;
        ipv4_addr_t dst_ip;
        bit<8>      protocol;
        bit<16>     src_port;
        bit<16>     dst_port;
    }

    action trigger_heavy_hitter_mitigation() {
        user_meta.security_meta.heavy_hitter_detected = 1#1;
        /* Demote traffic class or apply selective ECN */
        hdr.ipv4.dscp = DSCP_CS1;
    }

    apply {
        if (hdr.ipv4.isValid() && (hdr.tcp.isValid() || hdr.udp.isValid())) {
            flow_key_t key;
            key.src_ip = hdr.ipv4.src_addr;
            key.dst_ip = hdr.ipv4.dst_addr;
            key.protocol = hdr.ipv4.protocol;
            key.src_port = user_meta.parser_meta.l4_src_port;
            key.dst_port = user_meta.parser_meta.l4_dst_port;

            bit<16> idx0 = hash_stage_0.compute(key);
            bit<16> idx1 = hash_stage_1.compute(key);
            bit<16> idx2 = hash_stage_2.compute(key);
            bit<16> idx3 = hash_stage_3.compute(key);

            bit<32> c0 = sketch_row_0.read((bit<32>)idx0) + 1;
            bit<32> c1 = sketch_row_1.read((bit<32>)idx1) + 1;
            bit<32> c2 = sketch_row_2.read((bit<32>)idx2) + 1;
            bit<32> c3 = sketch_row_3.read((bit<32>)idx3) + 1;

            sketch_row_0.write((bit<32>)idx0, c0);
            sketch_row_1.write((bit<32>)idx1, c1);
            sketch_row_2.write((bit<32>)idx2, c2);
            sketch_row_3.write((bit<32>)idx3, c3);

            /* Calculate minimum across the 4 sketch estimates */
            bit<32> min_c = c0;
            if (c1 < min_c) min_c = c1;
            if (c2 < min_c) min_c = c2;
            if (c3 < min_c) min_c = c3;

            user_meta.security_meta.sketch_min_count = min_c;

            /* Heavy hitter threshold: 10,000 packets */
            if (min_c > 10000) {
                trigger_heavy_hitter_mitigation();
            }
        }
    }
}

#endif /* _CHOCK_SECURITY_COUNT_MIN_SKETCH_P4_ */
