/*
 * In-Band Network Telemetry (INT v2.1) Header Definitions (P4_16)
 *
 * Defines the telemetry shim header, telemetry metadata header, and hop-by-hop
 * stack entry formats conforming to the Telemetry Report Format Specification v2.1.
 */

#ifndef _CHOCK_TELEMETRY_INT_HEADERS_P4_
#define _CHOCK_TELEMETRY_INT_HEADERS_P4_

#include "../core/types.p4"

/*
 * INT Shim Header over TCP/UDP/Geneve (4 bytes)
 */
header int_shim_h {
    bit<4>  int_type;
    bit<2>  npt;
    bit<2>  reserved;
    bit<8>  length_words;
    bit<16> next_proto;
}

/*
 * INT Telemetry Metadata Header (8 bytes)
 */
header int_metadata_hdr_h {
    bit<4>  version;
    bit<2>  replication;
    bit<1>  c_flag;
    bit<1>  e_flag;
    bit<1>  m_flag;
    bit<7>  reserved;
    bit<8>  hop_limit;
    bit<8>  remaining_hop_cnt;
    bit<16> instruction_mask;
    bit<16> domain_specific_id;
}

/*
 * Standard INT Hop Metadata Vector Fields
 */
const bit<16> INT_INS_SWITCH_ID              = 16#8000;
const bit<16> INT_INS_INGRESS_EGRESS_PORT    = 16#4000;
const bit<16> INT_INS_HOP_LATENCY            = 16#2000;
const bit<16> INT_INS_QUEUE_OCCUPANCY        = 16#1000;
const bit<16> INT_INS_INGRESS_TIMESTAMP      = 16#0800;
const bit<16> INT_INS_EGRESS_TIMESTAMP       = 16#0400;
const bit<16> INT_INS_QUEUE_CONGESTION_STATUS = 16#0200;
const bit<16> INT_INS_EGRESS_PORT_TX_UTIL    = 16#0100;

header int_hop_switch_id_h {
    bit<32> switch_id;
}

header int_hop_ports_h {
    port_id_t ingress_port;
    bit<7>    pad0;
    port_id_t egress_port;
    bit<7>    pad1;
}

header int_hop_latency_h {
    latency_t hop_latency_ns;
}

header int_hop_queue_occupancy_h {
    bit<8>   queue_id;
    qdepth_t queue_depth_packets;
    bit<5>   reserved;
}

header int_hop_ingress_timestamp_h {
    timestamp_t ingress_timestamp_ns;
    bit<16>     reserved;
}

header int_hop_egress_timestamp_h {
    timestamp_t egress_timestamp_ns;
    bit<16>     reserved;
}

header int_hop_congestion_status_h {
    bit<1>  ecn_marked;
    bit<1>  dcqcn_cnp;
    bit<14> buffer_watermark_pct;
    bit<16> reserved;
}

/*
 * Postcard Telemetry (INT-XD) Notification Header
 */
header int_postcard_h {
    bit<4>      version;
    bit<4>      drop_reason;
    bit<8>      sequence_number;
    bit<16>     postcard_flags;
    bit<32>     switch_id;
    port_id_t   ingress_port;
    port_id_t   egress_port;
    bit<14>     reserved;
    qdepth_t    queue_depth;
    timestamp_t event_timestamp;
}

#endif /* _CHOCK_TELEMETRY_INT_HEADERS_P4_ */
