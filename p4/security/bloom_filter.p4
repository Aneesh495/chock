/*
 * Dual-Bank Counting Bloom Filter for SYN Flood Mitigation (P4_16)
 *
 * Tracks active TCP SYN handshakes in on-chip registers using dual independent
 * hash projections. Detects asymmetrical half-open SYN floods and triggers
 * hardware cookie generation.
 */

#ifndef _CHOCK_SECURITY_BLOOM_FILTER_P4_
#define _CHOCK_SECURITY_BLOOM_FILTER_P4_

#include "../arch/chock_arch.p4"
#include "../core/types.p4"
#include "../core/unified_headers.p4"
#include "../core/metadata.p4"

control ChockBloomFilter(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    ChockRegister<bit<1>>(65536, 0) bloom_bank_a;
    ChockRegister<bit<1>>(65536, 0) bloom_bank_b;

    ChockHash<bit<16>>(HashAlgorithm_t.HASH_CRC32) hash_a;
    ChockHash<bit<16>>(HashAlgorithm_t.HASH_MURMUR3) hash_b;

    struct tcp_handshake_key_t {
        ipv4_addr_t src_ip;
        ipv4_addr_t dst_ip;
        bit<16>     src_port;
        bit<16>     dst_port;
    }

    action trigger_syn_flood_protection() {
        user_meta.security_meta.tcp_syn_flood_detected = 1#1;
        /* Drop unverified SYN packets under attack */
        ig_to_eg_md.drop_flag = 1#1;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_DROP;
    }

    apply {
        if (hdr.tcp.isValid()) {
            tcp_handshake_key_t key;
            key.src_ip = hdr.ipv4.src_addr;
            key.dst_ip = hdr.ipv4.dst_addr;
            key.src_port = hdr.tcp.src_port;
            key.dst_port = hdr.tcp.dst_port;

            bit<16> idx_a = hash_a.compute(key);
            bit<16> idx_b = hash_b.compute(key);

            user_meta.security_meta.bloom_index_0 = idx_a;
            user_meta.security_meta.bloom_index_1 = idx_b;

            if (hdr.tcp.syn == 1#1 && hdr.tcp.ack == 1#0) {
                /* Inbound SYN: register in Bloom filter */
                bloom_bank_a.write((bit<32>)idx_a, 1#1);
                bloom_bank_b.write((bit<32>)idx_b, 1#1);
            } else if (hdr.tcp.ack == 1#1) {
                /* Inbound ACK: check if connection was initiated */
                bit<1> val_a = bloom_bank_a.read((bit<32>)idx_a);
                bit<1> val_b = bloom_bank_b.read((bit<32>)idx_b);

                if (val_a == 1#1 && val_b == 1#1) {
                    user_meta.security_meta.bloom_filter_match = 1#1;
                } else if (hdr.tcp.syn == 1#0) {
                    /* Spurious ACK without registered SYN */
                    user_meta.security_meta.bloom_filter_match = 1#0;
                }
            }
        }
    }
}

#endif /* _CHOCK_SECURITY_BLOOM_FILTER_P4_ */
