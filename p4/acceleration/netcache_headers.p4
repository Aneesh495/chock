/*
 * NetCache In-Network Key-Value Cache Protocol Header (P4_16)
 *
 * Defines the line-rate query and response protocol for on-chip key-value caching.
 */

#ifndef _CHOCK_ACCEL_NETCACHE_HEADERS_P4_
#define _CHOCK_ACCEL_NETCACHE_HEADERS_P4_

#include "../core/types.p4"

const bit<8> NETCACHE_OP_READ          = 8#01;
const bit<8> NETCACHE_OP_READ_REPLY    = 8#02;
const bit<8> NETCACHE_OP_WRITE         = 8#03;
const bit<8> NETCACHE_OP_WRITE_REPLY   = 8#04;
const bit<8> NETCACHE_OP_HOT_REPORT    = 8#05;
const bit<8> NETCACHE_OP_INVALIDATE    = 8#06;

header netcache_h {
    bit<8>   op;
    bit<8>   status;
    bit<16>  seq_id;
    bit<64>  key;
    bit<128> val;
}

#endif /* _CHOCK_ACCEL_NETCACHE_HEADERS_P4_ */
