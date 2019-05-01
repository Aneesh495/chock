/*
 * NetCache In-Network Key-Value Storage Query Handler (P4_16)
 *
 * Implements line-rate key-value caching in switch on-chip SRAM registers.
 * Intercepts read queries, executes single-cycle hash lookup, serves cache hits
 * directly in data plane, and forwards misses to backend storage servers.
 */

#ifndef _CHOCK_ACCEL_NETCACHE_P4_
#define _CHOCK_ACCEL_NETCACHE_P4_

#include "../arch/chock_arch.p4"
#include "../core/types.p4"
#include "../core/unified_headers.p4"
#include "../core/metadata.p4"
#include "netcache_headers.p4"

control ChockNetCache(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    /* 16,384 on-chip cache slots */
    ChockRegister<bit<64>>(16384, 0)   cache_keys;
    ChockRegister<bit<128>>(16384, 0)  cache_values;
    ChockRegister<bit<1>>(16384, 0)    cache_valid;
    ChockRegister<bit<32>>(16384, 0)   cache_frequency;

    ChockHash<bit<14>>(HashAlgorithm_t.HASH_CRC32) key_hasher;

    action serve_cache_hit(bit<128> cached_val) {
        hdr.netcache.op = NETCACHE_OP_READ_REPLY;
        hdr.netcache.status = 8#00; /* Success */
        hdr.netcache.val = cached_val;

        /* Swap Ethernet MAC addresses */
        mac_addr_t tmp_mac = hdr.ethernet.src_addr;
        hdr.ethernet.src_addr = hdr.ethernet.dst_addr;
        hdr.ethernet.dst_addr = tmp_mac;

        /* Swap IP addresses */
        ipv4_addr_t tmp_ip = hdr.ipv4.src_addr;
        hdr.ipv4.src_addr = hdr.ipv4.dst_addr;
        hdr.ipv4.dst_addr = tmp_ip;

        /* Swap UDP ports */
        bit<16> tmp_port = hdr.udp.src_port;
        hdr.udp.src_port = hdr.udp.dst_port;
        hdr.udp.dst_port = tmp_port;

        /* Send back on ingress port */
        ig_to_eg_md.egress_port = ig_intr_md.ingress_port;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_UNICAST;

        user_meta.accel_meta.netcache_cache_hit = 1#1;
    }

    action forward_to_backend_storage(port_id_t server_port) {
        ig_to_eg_md.egress_port = server_port;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_UNICAST;
        user_meta.accel_meta.netcache_cache_hit = 1#0;
    }

    apply {
        if (hdr.netcache.isValid() && hdr.netcache.op == NETCACHE_OP_READ) {
            bit<14> slot_idx = key_hasher.compute(hdr.netcache.key);
            bit<32> idx = (bit<32>)slot_idx;

            bit<1> is_valid = cache_valid.read(idx);
            bit<64> registered_key = cache_keys.read(idx);

            /* Increment key access frequency counter */
            bit<32> freq = cache_frequency.read(idx);
            cache_frequency.write(idx, freq + 1);

            if (is_valid == 1#1 && registered_key == hdr.netcache.key) {
                bit<128> val = cache_values.read(idx);
                serve_cache_hit(val);
            } else {
                forward_to_backend_storage(2);
            }
        }
    }
}

#endif /* _CHOCK_ACCEL_NETCACHE_P4_ */
