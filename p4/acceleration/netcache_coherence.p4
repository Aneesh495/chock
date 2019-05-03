/*
 * NetCache Write Invalidation and Coherency Pipeline (P4_16)
 *
 * Intercepts write mutations and invalidates on-chip cache slots to maintain
 * strict read-after-write consistency between switch data plane and servers.
 */

#ifndef _CHOCK_ACCEL_NETCACHE_COHERENCE_P4_
#define _CHOCK_ACCEL_NETCACHE_COHERENCE_P4_

#include "../arch/chock_arch.p4"
#include "../core/types.p4"
#include "../core/unified_headers.p4"
#include "../core/metadata.p4"
#include "netcache_headers.p4"

control ChockNetCacheCoherence(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    ChockRegister<bit<64>>(16384, 0)   cache_keys;
    ChockRegister<bit<128>>(16384, 0)  cache_values;
    ChockRegister<bit<1>>(16384, 0)    cache_valid;

    ChockHash<bit<14>>(HashAlgorithm_t.HASH_CRC32) key_hasher;

    apply {
        if (hdr.netcache.isValid()) {
            if (hdr.netcache.op == NETCACHE_OP_WRITE || hdr.netcache.op == NETCACHE_OP_INVALIDATE) {
                bit<14> slot_idx = key_hasher.compute(hdr.netcache.key);
                bit<32> idx = (bit<32>)slot_idx;

                bit<64> registered_key = cache_keys.read(idx);
                if (registered_key == hdr.netcache.key) {
                    /* Invalidate cache slot */
                    cache_valid.write(idx, 1#0);
                }
            }
        }
    }
}

#endif /* _CHOCK_ACCEL_NETCACHE_COHERENCE_P4_ */
