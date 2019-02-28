/*
 * Chock Multi-Protocol Header Parser (P4_16)
 *
 * Implements a recursive descent packet parsing state machine handling L2, L3, L4,
 * tunneling encapsulations, SRv6 segment lists, In-Band Network Telemetry,
 * and high-frequency in-network compute acceleration headers.
 */

#ifndef _CHOCK_CORE_PARSER_P4_
#define _CHOCK_CORE_PARSER_P4_

#include "../arch/chock_arch.p4"
#include "types.p4"
#include "unified_headers.p4"
#include "metadata.p4"

parser ChockTopParser(
    packet_in pkt,
    out headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md
) {
    /*
     * Parser Entry Point
     */
    state start {
        user_meta.parser_meta.is_ethernet_valid = 1#0;
        user_meta.parser_meta.is_vlan_valid = 1#0;
        user_meta.parser_meta.is_provider_vlan_valid = 1#0;
        user_meta.parser_meta.is_arp_valid = 1#0;
        user_meta.parser_meta.is_ipv4_valid = 1#0;
        user_meta.parser_meta.is_ipv6_valid = 1#0;
        user_meta.parser_meta.is_tcp_valid = 1#0;
        user_meta.parser_meta.is_udp_valid = 1#0;
        user_meta.parser_meta.is_icmpv4_valid = 1#0;
        user_meta.parser_meta.is_icmpv6_valid = 1#0;
        user_meta.parser_meta.is_gre_valid = 1#0;
        user_meta.parser_meta.is_nvgre_valid = 1#0;
        user_meta.parser_meta.is_vxlan_valid = 1#0;
        user_meta.parser_meta.is_geneve_valid = 1#0;
        user_meta.parser_meta.is_mpls_valid = 1#0;
        user_meta.parser_meta.is_srv6_valid = 1#0;
        user_meta.parser_meta.is_int_valid = 1#0;
        user_meta.parser_meta.is_netcache_valid = 1#0;
        user_meta.parser_meta.is_netpaxos_valid = 1#0;
        user_meta.parser_meta.is_market_feed_valid = 1#0;
        user_meta.parser_meta.payload_offset_bytes = 0;
        user_meta.parser_meta.parser_error_code = error.NoError;
        transition parse_ethernet;
    }

    /*
     * Parse Ethernet MAC Header
     */
    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        user_meta.parser_meta.is_ethernet_valid = 1#1;
        user_meta.l2_meta.ingress_vlan_id = 0;
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_PROVIDER_VLAN: parse_provider_vlan;
            ETHERTYPE_VLAN:          parse_vlan;
            ETHERTYPE_ARP:           parse_arp;
            ETHERTYPE_MPLS_UNICAST:  parse_mpls_0;
            ETHERTYPE_MPLS_MULTICAST: parse_mpls_0;
            ETHERTYPE_IPV4:          parse_ipv4;
            ETHERTYPE_IPV6:          parse_ipv6;
            default: accept;
        }
    }

    /*
     * Parse 802.1ad Service Provider Tag (QinQ outer tag)
     */
    state parse_provider_vlan {
        pkt.extract(hdr.provider_vlan);
        user_meta.parser_meta.is_provider_vlan_valid = 1#1;
        transition select(hdr.provider_vlan.ether_type) {
            ETHERTYPE_VLAN: parse_vlan;
            ETHERTYPE_IPV4: parse_ipv4;
            ETHERTYPE_IPV6: parse_ipv6;
            default: accept;
        }
    }

    /*
     * Parse 802.1Q Customer VLAN Tag
     */
    state parse_vlan {
        pkt.extract(hdr.vlan);
        user_meta.parser_meta.is_vlan_valid = 1#1;
        user_meta.l2_meta.ingress_vlan_id = hdr.vlan.vid;
        user_meta.l2_meta.vlan_pcp = hdr.vlan.pcp;
        user_meta.l2_meta.vlan_cfi = hdr.vlan.dei;
        transition select(hdr.vlan.ether_type) {
            ETHERTYPE_ARP:  parse_arp;
            ETHERTYPE_IPV4: parse_ipv4;
            ETHERTYPE_IPV6: parse_ipv6;
            ETHERTYPE_MPLS_UNICAST: parse_mpls_0;
            default: accept;
        }
    }

    /*
     * Parse Address Resolution Protocol (ARP)
     */
    state parse_arp {
        pkt.extract(hdr.arp);
        user_meta.parser_meta.is_arp_valid = 1#1;
        transition accept;
    }

    /*
     * Parse MPLS Label Stack (supporting up to 3 labels)
     */
    state parse_mpls_0 {
        pkt.extract(hdr.mpls_0);
        user_meta.parser_meta.is_mpls_valid = 1#1;
        transition select(hdr.mpls_0.bottom_of_stack) {
            1#1: parse_mpls_payload;
            1#0: parse_mpls_1;
        }
    }

    state parse_mpls_1 {
        pkt.extract(hdr.mpls_1);
        transition select(hdr.mpls_1.bottom_of_stack) {
            1#1: parse_mpls_payload;
            1#0: parse_mpls_2;
        }
    }

    state parse_mpls_2 {
        pkt.extract(hdr.mpls_2);
        transition parse_mpls_payload;
    }

    state parse_mpls_payload {
        transition select(pkt.lookahead<bit<4>>()) {
            4#4: parse_ipv4;
            4#6: parse_ipv6;
            default: accept;
        }
    }

    /*
     * Parse IPv4 Header
     */
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        user_meta.parser_meta.is_ipv4_valid = 1#1;
        user_meta.traffic_meta.traffic_class = hdr.ipv4.dscp[5:3];
        transition select(hdr.ipv4.protocol) {
            IP_PROTO_TCP:    parse_tcp;
            IP_PROTO_UDP:    parse_udp;
            IP_PROTO_ICMP:   parse_icmpv4;
            IP_PROTO_GRE:    parse_gre;
            IP_PROTO_NVGRE:  parse_nvgre;
            IP_PROTO_IPV6_ENCAP: parse_inner_ipv6;
            default: accept;
        }
    }

    /*
     * Parse IPv6 Header
     */
    state parse_ipv6 {
        pkt.extract(hdr.ipv6);
        user_meta.parser_meta.is_ipv6_valid = 1#1;
        user_meta.traffic_meta.traffic_class = hdr.ipv6.traffic_class[7:5];
        transition select(hdr.ipv6.next_hdr) {
            IP_PROTO_IPV6_ROUTE: parse_srv6_srh;
            IP_PROTO_TCP:        parse_tcp;
            IP_PROTO_UDP:        parse_udp;
            IP_PROTO_IPV6_ICMP:  parse_icmpv6;
            IP_PROTO_GRE:        parse_gre;
            default: accept;
        }
    }

    /*
     * Parse SRv6 Segment Routing Header (SRH)
     */
    state parse_srv6_srh {
        pkt.extract(hdr.srv6_srh);
        user_meta.parser_meta.is_srv6_valid = 1#1;
        user_meta.srv6_meta.srv6_active = 1#1;
        user_meta.srv6_meta.segments_left = hdr.srv6_srh.segments_left;
        user_meta.srv6_meta.last_entry = hdr.srv6_srh.last_entry;
        user_meta.srv6_meta.flags = hdr.srv6_srh.flags;
        user_meta.srv6_meta.tag = hdr.srv6_srh.tag;
        transition select(hdr.srv6_srh.last_entry) {
            0: parse_srv6_seg0;
            1: parse_srv6_seg0;
            2: parse_srv6_seg0;
            3: parse_srv6_seg0;
            default: parse_srv6_seg0;
        }
    }

    state parse_srv6_seg0 {
        pkt.extract(hdr.srv6_seg0);
        transition select(hdr.srv6_srh.last_entry) {
            0: parse_srv6_next_proto;
            default: parse_srv6_seg1;
        }
    }

    state parse_srv6_seg1 {
        pkt.extract(hdr.srv6_seg1);
        transition select(hdr.srv6_srh.last_entry) {
            1: parse_srv6_next_proto;
            default: parse_srv6_seg2;
        }
    }

    state parse_srv6_seg2 {
        pkt.extract(hdr.srv6_seg2);
        transition select(hdr.srv6_srh.last_entry) {
            2: parse_srv6_next_proto;
            default: parse_srv6_seg3;
        }
    }

    state parse_srv6_seg3 {
        pkt.extract(hdr.srv6_seg3);
        transition parse_srv6_next_proto;
    }

    state parse_srv6_next_proto {
        transition select(hdr.srv6_srh.next_hdr) {
            IP_PROTO_TCP: parse_tcp;
            IP_PROTO_UDP: parse_udp;
            IP_PROTO_IPV4_ENCAP: parse_inner_ipv4;
            IP_PROTO_IPV6_ENCAP: parse_inner_ipv6;
            IP_PROTO_ETHERNET_IN_IP: parse_inner_ethernet;
            default: accept;
        }
    }

    /*
     * Parse TCP Header
     */
    state parse_tcp {
        pkt.extract(hdr.tcp);
        user_meta.parser_meta.is_tcp_valid = 1#1;
        user_meta.parser_meta.l4_src_port = hdr.tcp.src_port;
        user_meta.parser_meta.l4_dst_port = hdr.tcp.dst_port;
        transition accept;
    }

    /*
     * Parse UDP Header
     */
    state parse_udp {
        pkt.extract(hdr.udp);
        user_meta.parser_meta.is_udp_valid = 1#1;
        user_meta.parser_meta.l4_src_port = hdr.udp.src_port;
        user_meta.parser_meta.l4_dst_port = hdr.udp.dst_port;
        transition select(hdr.udp.dst_port) {
            UDP_PORT_VXLAN:          parse_vxlan;
            UDP_PORT_GENEVE:         parse_geneve;
            UDP_PORT_NETCACHE:       parse_netcache;
            UDP_PORT_NETPAXOS:       parse_netpaxos;
            UDP_PORT_MARKET_FEED_A:  parse_market_feed;
            UDP_PORT_MARKET_FEED_B:  parse_market_feed;
            UDP_PORT_INT_REPORT:     parse_int_shim;
            default: accept;
        }
    }

    /*
     * Parse ICMPv4 Header
     */
    state parse_icmpv4 {
        pkt.extract(hdr.icmpv4);
        user_meta.parser_meta.is_icmpv4_valid = 1#1;
        transition accept;
    }

    /*
     * Parse ICMPv6 Header
     */
    state parse_icmpv6 {
        pkt.extract(hdr.icmpv6);
        user_meta.parser_meta.is_icmpv6_valid = 1#1;
        transition accept;
    }

    /*
     * Parse GRE Header
     */
    state parse_gre {
        pkt.extract(hdr.gre);
        user_meta.parser_meta.is_gre_valid = 1#1;
        transition select(hdr.gre.protocol_type) {
            ETHERTYPE_IPV4: parse_inner_ipv4;
            ETHERTYPE_IPV6: parse_inner_ipv6;
            default: accept;
        }
    }

    /*
     * Parse NVGRE Header
     */
    state parse_nvgre {
        pkt.extract(hdr.nvgre);
        user_meta.parser_meta.is_nvgre_valid = 1#1;
        transition select(hdr.nvgre.protocol_type) {
            ETHERTYPE_IPV4: parse_inner_ipv4;
            ETHERTYPE_IPV6: parse_inner_ipv6;
            default: accept;
        }
    }

    /*
     * Parse VXLAN Header
     */
    state parse_vxlan {
        pkt.extract(hdr.vxlan);
        user_meta.parser_meta.is_vxlan_valid = 1#1;
        transition parse_inner_ethernet;
    }

    /*
     * Parse Geneve Header
     */
    state parse_geneve {
        pkt.extract(hdr.geneve);
        user_meta.parser_meta.is_geneve_valid = 1#1;
        transition select(hdr.geneve.protocol_type) {
            ETHERTYPE_IPV4: parse_inner_ipv4;
            ETHERTYPE_IPV6: parse_inner_ipv6;
            default: parse_inner_ethernet;
        }
    }

    /*
     * Parse In-Band Network Telemetry (INT v2.1)
     */
    state parse_int_shim {
        pkt.extract(hdr.int_shim);
        user_meta.parser_meta.is_int_valid = 1#1;
        user_meta.int_meta.int_active = 1#1;
        transition parse_int_metadata_hdr;
    }

    state parse_int_metadata_hdr {
        pkt.extract(hdr.int_metadata_hdr);
        user_meta.int_meta.int_version = hdr.int_metadata_hdr.version;
        user_meta.int_meta.int_replication = hdr.int_metadata_hdr.replication;
        user_meta.int_meta.int_c_flag = hdr.int_metadata_hdr.c_flag;
        user_meta.int_meta.int_e_flag = hdr.int_metadata_hdr.e_flag;
        user_meta.int_meta.int_m_flag = hdr.int_metadata_hdr.m_flag;
        user_meta.int_meta.instruction_mask = hdr.int_metadata_hdr.instruction_mask;
        user_meta.int_meta.remaining_hop_cnt = hdr.int_metadata_hdr.remaining_hop_cnt;
        transition select(hdr.int_metadata_hdr.remaining_hop_cnt) {
            0: accept;
            default: parse_int_hop_switch_id;
        }
    }

    state parse_int_hop_switch_id {
        pkt.extract(hdr.int_hop_switch_id);
        transition parse_int_hop_ports;
    }

    state parse_int_hop_ports {
        pkt.extract(hdr.int_hop_ports);
        transition parse_int_hop_latency;
    }

    state parse_int_hop_latency {
        pkt.extract(hdr.int_hop_latency);
        transition parse_int_hop_queue_occupancy;
    }

    state parse_int_hop_queue_occupancy {
        pkt.extract(hdr.int_hop_queue_occupancy);
        transition accept;
    }

    /*
     * Parse NetCache Query Header
     */
    state parse_netcache {
        pkt.extract(hdr.netcache);
        user_meta.parser_meta.is_netcache_valid = 1#1;
        user_meta.accel_meta.netcache_opcode = hdr.netcache.op;
        user_meta.accel_meta.netcache_key = hdr.netcache.key;
        user_meta.accel_meta.netcache_value = hdr.netcache.val;
        transition accept;
    }

    /*
     * Parse NetPaxos Consensus Header
     */
    state parse_netpaxos {
        pkt.extract(hdr.netpaxos);
        user_meta.parser_meta.is_netpaxos_valid = 1#1;
        user_meta.accel_meta.netpaxos_message_type = hdr.netpaxos.msg_type;
        user_meta.accel_meta.netpaxos_instance_id = hdr.netpaxos.instance_id;
        user_meta.accel_meta.netpaxos_round_id = (bit<32>)hdr.netpaxos.round;
        transition accept;
    }

    /*
     * Parse Market Feed Header
     */
    state parse_market_feed {
        pkt.extract(hdr.market_feed);
        user_meta.parser_meta.is_market_feed_valid = 1#1;
        user_meta.accel_meta.market_feed_sequence_no = hdr.market_feed.sequence_number;
        user_meta.accel_meta.market_feed_channel_id = hdr.market_feed.channel_id;
        transition accept;
    }

    /*
     * Inner Protocol Parsers for Decapsulation
     */
    state parse_inner_ethernet {
        pkt.extract(hdr.inner_ethernet);
        transition select(hdr.inner_ethernet.ether_type) {
            ETHERTYPE_IPV4: parse_inner_ipv4;
            ETHERTYPE_IPV6: parse_inner_ipv6;
            default: accept;
        }
    }

    state parse_inner_ipv4 {
        pkt.extract(hdr.inner_ipv4);
        transition select(hdr.inner_ipv4.protocol) {
            IP_PROTO_TCP: parse_inner_tcp;
            IP_PROTO_UDP: parse_inner_udp;
            default: accept;
        }
    }

    state parse_inner_ipv6 {
        pkt.extract(hdr.inner_ipv6);
        transition select(hdr.inner_ipv6.next_hdr) {
            IP_PROTO_TCP: parse_inner_tcp;
            IP_PROTO_UDP: parse_inner_udp;
            default: accept;
        }
    }

    state parse_inner_tcp {
        pkt.extract(hdr.inner_tcp);
        transition accept;
    }

    state parse_inner_udp {
        pkt.extract(hdr.inner_udp);
        transition accept;
    }
}

#endif /* _CHOCK_CORE_PARSER_P4_ */
