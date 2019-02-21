/*
 * Chock User and Pipeline Metadata Structures (P4_16)
 *
 * Defines the cross-stage user metadata container encompassing parser status,
 * forwarding decisions, routing lookup results, traffic telemetry, security
 * tracking, and in-network compute acceleration state.
 */

#ifndef _CHOCK_CORE_METADATA_P4_
#define _CHOCK_CORE_METADATA_P4_

#include "types.p4"

/*
 * Parser Status Metadata
 */
struct parser_metadata_t {
    bit<1>  is_ethernet_valid;
    bit<1>  is_vlan_valid;
    bit<1>  is_provider_vlan_valid;
    bit<1>  is_arp_valid;
    bit<1>  is_ipv4_valid;
    bit<1>  is_ipv6_valid;
    bit<1>  is_tcp_valid;
    bit<1>  is_udp_valid;
    bit<1>  is_icmpv4_valid;
    bit<1>  is_icmpv6_valid;
    bit<1>  is_gre_valid;
    bit<1>  is_nvgre_valid;
    bit<1>  is_vxlan_valid;
    bit<1>  is_geneve_valid;
    bit<1>  is_mpls_valid;
    bit<1>  is_srv6_valid;
    bit<1>  is_int_valid;
    bit<1>  is_roce_valid;
    bit<1>  is_netcache_valid;
    bit<1>  is_netpaxos_valid;
    bit<1>  is_market_feed_valid;
    bit<16> l4_src_port;
    bit<16> l4_dst_port;
    bit<16> payload_offset_bytes;
    error   parser_error_code;
}

/*
 * Layer 2 Switching and Bridging Metadata
 */
struct l2_metadata_t {
    vlan_id_t  ingress_vlan_id;
    vlan_id_t  egress_vlan_id;
    bit<3>     vlan_pcp;
    bit<1>     vlan_cfi;
    bit<1>     mac_learn_required;
    bit<1>     l2_lookup_hit;
    bit<1>     is_broadcast;
    bit<1>     is_multicast;
    bit<1>     split_horizon_drop;
    port_id_t  l2_egress_port;
}

/*
 * Layer 3 Routing and Forwarding Metadata
 */
struct l3_metadata_t {
    vrf_id_t    vrf_id;
    ipv4_addr_t next_hop_ipv4;
    ipv6_addr_t next_hop_ipv6;
    mac_addr_t  next_hop_mac;
    mac_addr_t  source_router_mac;
    port_id_t   l3_egress_port;
    bit<1>      l3_route_hit;
    bit<1>      ttl_expired;
    bit<1>      hop_limit_expired;
    bit<1>      mtu_exceeded;
    bit<16>     route_metric;
    bit<8>      ecmp_group_id;
    bit<16>     ecmp_hash_val;
    bit<8>      ecmp_member_index;
    bit<1>      send_icmp_time_exceeded;
    bit<1>      send_icmp_unreachable;
}

/*
 * Segment Routing over IPv6 (SRv6) Metadata
 */
struct srv6_metadata_t {
    bit<1>      srv6_active;
    bit<8>      segments_left;
    bit<8>      last_entry;
    bit<8>      flags;
    bit<16>     tag;
    ipv6_addr_t current_sid;
    ipv6_addr_t next_sid;
    bit<8>      srv6_endpoint_behavior;
    vrf_id_t    srv6_target_vrf;
    port_id_t   srv6_target_port;
    bit<1>      srv6_decap_required;
    bit<1>      srv6_encap_required;
}

/*
 * In-Band Network Telemetry (INT v2.1) Metadata
 */
struct int_metadata_t {
    bit<1>      int_active;
    bit<4>      int_version;
    bit<2>      int_replication;
    bit<1>      int_c_flag;
    bit<1>      int_e_flag;
    bit<1>      int_m_flag;
    bit<16>     instruction_mask;
    bit<8>      remaining_hop_cnt;
    bit<8>      total_hop_cnt;
    bit<32>     switch_id;
    latency_t   hop_latency_ns;
    qdepth_t    queue_occupancy;
    timestamp_t ingress_ts;
    timestamp_t egress_ts;
    bit<1>      int_source_node;
    bit<1>      int_transit_node;
    bit<1>      int_sink_node;
    bit<1>      int_mirror_report;
}

/*
 * Congestion, Flowlet, and Active Queue Management Metadata
 */
struct traffic_metadata_t {
    flow_id_t    flow_id;
    bit<16>      flowlet_id;
    timestamp_t  last_arrival_timestamp;
    bit<32>      inter_arrival_gap_us;
    bit<1>       flowlet_burst_boundary;
    port_id_t    flowlet_selected_path;
    bit<1>       dcqcn_marked;
    bit<1>       dcqcn_cnp_generated;
    bit<1>       ecn_congestion_experienced;
    qdepth_t     instantaneous_queue_depth;
    qdepth_t     ewma_queue_depth;
    bit<3>       traffic_class;
    MeterColor_t meter_result_color;
}

/*
 * Security, Flow Accounting, and Stateful Tracking Metadata
 */
struct security_metadata_t {
    bit<1>      acl_permit;
    bit<1>      acl_deny;
    bit<1>      acl_mirror;
    bit<1>      acl_rate_limit;
    bit<32>     acl_matched_rule_id;
    bit<1>      heavy_hitter_detected;
    bit<32>     sketch_hash_0;
    bit<32>     sketch_hash_1;
    bit<32>     sketch_hash_2;
    bit<32>     sketch_hash_3;
    bit<32>     sketch_min_count;
    bit<1>      bloom_filter_match;
    bit<16>     bloom_index_0;
    bit<16>     bloom_index_1;
    bit<1>      tcp_syn_flood_detected;
    bit<32>     syn_cookie_calculated;
    bit<1>      nat64_translation_hit;
}

/*
 * In-Network Compute Acceleration Metadata
 */
struct accel_metadata_t {
    bit<8>      netcache_opcode;
    bit<64>     netcache_key;
    bit<128>    netcache_value;
    bit<1>      netcache_cache_hit;
    bit<1>      netcache_read_query;
    bit<1>      netcache_write_query;
    bit<8>      netpaxos_message_type;
    bit<32>     netpaxos_instance_id;
    bit<32>     netpaxos_round_id;
    bit<32>     netpaxos_assigned_sequence;
    bit<1>      netpaxos_sequence_stamped;
    bit<32>     market_feed_sequence_no;
    bit<8>      market_feed_channel_id;
    bit<1>      market_feed_packet_dropped;
    bit<1>      market_feed_is_duplicate;
}

/*
 * Complete User Metadata Container (carried across all pipeline stages)
 */
struct user_metadata_t {
    parser_metadata_t   parser_meta;
    l2_metadata_t       l2_meta;
    l3_metadata_t       l3_meta;
    srv6_metadata_t     srv6_meta;
    int_metadata_t      int_meta;
    traffic_metadata_t  traffic_meta;
    security_metadata_t security_meta;
    accel_metadata_t    accel_meta;
}

#endif /* _CHOCK_CORE_METADATA_P4_ */\n