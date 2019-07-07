/*
 * IPv4 Longest Prefix Match (LPM) Routing Pipeline (P4_16)
 *
 * Implements CIDR prefix table lookup, VRF routing domains, TTL validation,
 * next-hop MAC resolution, and ICMP time exceeded triggers.
 */

#ifndef _CHOCK_ROUTING_IPV4_LPM_P4_
#define _CHOCK_ROUTING_IPV4_LPM_P4_

#include "../arch/chock_arch.p4"
#include "../core/types.p4"
#include "../core/unified_headers.p4"
#include "../core/metadata.p4"

control ChockIpv4LpmRoute(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    ChockCounter(65536, CounterType_t.PACKETS_AND_BYTES) ipv4_route_counters;

    action set_next_hop_unicast(
        port_id_t   egress_port,
        ipv4_addr_t next_hop_ip,
        mac_addr_t  next_hop_mac,
        mac_addr_t  src_router_mac
    ) {
        ig_to_eg_md.egress_port = egress_port;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_UNICAST;
        user_meta.l3_meta.next_hop_ipv4 = next_hop_ip;
        user_meta.l3_meta.next_hop_mac = next_hop_mac;
        user_meta.l3_meta.source_router_mac = src_router_mac;
        user_meta.l3_meta.l3_route_hit = 1#1;

        hdr.ethernet.src_addr = src_router_mac;
        hdr.ethernet.dst_addr = next_hop_mac;
    }

    action set_ecmp_group(bit<8> ecmp_group_id) {
        user_meta.l3_meta.ecmp_group_id = ecmp_group_id;
        user_meta.l3_meta.l3_route_hit = 1#1;
    }

    action drop_unreachable() {
        ig_to_eg_md.drop_flag = 1#1;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_DROP;
        user_meta.l3_meta.send_icmp_unreachable = 1#1;
    }

    table ipv4_fib_lpm {
        key = {
            user_meta.l3_meta.vrf_id: exact;
            hdr.ipv4.dst_addr:        lpm;
        }
        actions = {
            set_next_hop_unicast;
            set_ecmp_group;
            drop_unreachable;
        }
        size = 65536;
        default_action = drop_unreachable();
    }

    apply {
        if (hdr.ipv4.isValid()) {
            /*
             * Check Time-to-Live (TTL)
             */
            if (hdr.ipv4.ttl <= 8#01) {
                user_meta.l3_meta.ttl_expired = 1#1;
                user_meta.l3_meta.send_icmp_time_exceeded = 1#1;
                ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_TO_CPU;
            } else {
                hdr.ipv4.ttl = hdr.ipv4.ttl - 8#01;
                ipv4_fib_lpm.apply();
                ipv4_route_counters.count((bit<32>)user_meta.l3_meta.vrf_id);
            }
        }
    }
}


/*
 * Comprehensive Match-Action Processing Pipeline for Ipv4LpmEngine
 * Implements hardware TCAM, SRAM, and stateful ALU execution stages.
 */

control ChockIpv4LpmEngineStage0(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    ChockRegister<bit<32>>(2048, 0) stage_state_reg;
    ChockCounter(2048, CounterType_t.PACKETS_AND_BYTES) stage_counter;
    ChockMeter(2048) stage_meter;

    action execute_ipv4lpmengine_stage0_act0(
        port_id_t  target_port,
        bit<16>    flow_metric,
        bit<8>     qos_class,
        mac_addr_t rewrite_mac
    ) {
        ig_to_eg_md.egress_port = target_port;
        ig_to_eg_md.traffic_class = qos_class[2:0];
        user_meta.l3_meta.route_metric = flow_metric;
        stage_counter.count((bit<32>)target_port);
        bit<32> prev_state = stage_state_reg.read((bit<32>)target_port);
        stage_state_reg.write((bit<32>)target_port, prev_state + 1);
    }

    action execute_ipv4lpmengine_stage0_act1(
        port_id_t  target_port,
        bit<16>    flow_metric,
        bit<8>     qos_class,
        mac_addr_t rewrite_mac
    ) {
        ig_to_eg_md.egress_port = target_port;
        ig_to_eg_md.traffic_class = qos_class[2:0];
        user_meta.l3_meta.route_metric = flow_metric;
        stage_counter.count((bit<32>)target_port);
        bit<32> prev_state = stage_state_reg.read((bit<32>)target_port);
        stage_state_reg.write((bit<32>)target_port, prev_state + 1);
    }

    action execute_ipv4lpmengine_stage0_act2(
        port_id_t  target_port,
        bit<16>    flow_metric,
        bit<8>     qos_class,
        mac_addr_t rewrite_mac
    ) {
        ig_to_eg_md.egress_port = target_port;
        ig_to_eg_md.traffic_class = qos_class[2:0];
        user_meta.l3_meta.route_metric = flow_metric;
        stage_counter.count((bit<32>)target_port);
        bit<32> prev_state = stage_state_reg.read((bit<32>)target_port);
        stage_state_reg.write((bit<32>)target_port, prev_state + 1);
    }

    action execute_ipv4lpmengine_stage0_act3(
        port_id_t  target_port,
        bit<16>    flow_metric,
        bit<8>     qos_class,
        mac_addr_t rewrite_mac
    ) {
        ig_to_eg_md.egress_port = target_port;
        ig_to_eg_md.traffic_class = qos_class[2:0];
        user_meta.l3_meta.route_metric = flow_metric;
        stage_counter.count((bit<32>)target_port);
        bit<32> prev_state = stage_state_reg.read((bit<32>)target_port);
        stage_state_reg.write((bit<32>)target_port, prev_state + 1);
    }

    action drop_ipv4lpmengine_stage0(bit<8> drop_code) {
        ig_to_eg_md.drop_flag = 1#1;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_DROP;
    }

    table ipv4lpmengine_stage0_table {
        key = {
            ig_intr_md.ingress_port:           exact;
            user_meta.l2_meta.ingress_vlan_id: ternary;
            hdr.ipv4.dst_addr:                 ternary;
            hdr.ipv4.src_addr:                 ternary;
            hdr.ipv4.protocol:                 ternary;
            user_meta.parser_meta.l4_src_port: ternary;
            user_meta.parser_meta.l4_dst_port: ternary;
        }
        actions = {
            execute_ipv4lpmengine_stage0_act0;
            execute_ipv4lpmengine_stage0_act1;
            execute_ipv4lpmengine_stage0_act2;
            execute_ipv4lpmengine_stage0_act3;
            drop_ipv4lpmengine_stage0;
            NoAction;
        }
        size = 2048;
        default_action = NoAction();
    }

    apply {
        ipv4lpmengine_stage0_table.apply();
    }
}

control ChockIpv4LpmEngineStage1(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    ChockRegister<bit<32>>(2048, 0) stage_state_reg;
    ChockCounter(2048, CounterType_t.PACKETS_AND_BYTES) stage_counter;
    ChockMeter(2048) stage_meter;

    action execute_ipv4lpmengine_stage1_act0(
        port_id_t  target_port,
        bit<16>    flow_metric,
        bit<8>     qos_class,
        mac_addr_t rewrite_mac
    ) {
        ig_to_eg_md.egress_port = target_port;
        ig_to_eg_md.traffic_class = qos_class[2:0];
        user_meta.l3_meta.route_metric = flow_metric;
        stage_counter.count((bit<32>)target_port);
        bit<32> prev_state = stage_state_reg.read((bit<32>)target_port);
        stage_state_reg.write((bit<32>)target_port, prev_state + 1);
    }

    action execute_ipv4lpmengine_stage1_act1(
        port_id_t  target_port,
        bit<16>    flow_metric,
        bit<8>     qos_class,
        mac_addr_t rewrite_mac
    ) {
        ig_to_eg_md.egress_port = target_port;
        ig_to_eg_md.traffic_class = qos_class[2:0];
        user_meta.l3_meta.route_metric = flow_metric;
        stage_counter.count((bit<32>)target_port);
        bit<32> prev_state = stage_state_reg.read((bit<32>)target_port);
        stage_state_reg.write((bit<32>)target_port, prev_state + 1);
    }

    action execute_ipv4lpmengine_stage1_act2(
        port_id_t  target_port,
        bit<16>    flow_metric,
        bit<8>     qos_class,
        mac_addr_t rewrite_mac
    ) {
        ig_to_eg_md.egress_port = target_port;
        ig_to_eg_md.traffic_class = qos_class[2:0];
        user_meta.l3_meta.route_metric = flow_metric;
        stage_counter.count((bit<32>)target_port);
        bit<32> prev_state = stage_state_reg.read((bit<32>)target_port);
        stage_state_reg.write((bit<32>)target_port, prev_state + 1);
    }

    action execute_ipv4lpmengine_stage1_act3(
        port_id_t  target_port,
        bit<16>    flow_metric,
        bit<8>     qos_class,
        mac_addr_t rewrite_mac
    ) {
        ig_to_eg_md.egress_port = target_port;
        ig_to_eg_md.traffic_class = qos_class[2:0];
        user_meta.l3_meta.route_metric = flow_metric;
        stage_counter.count((bit<32>)target_port);
        bit<32> prev_state = stage_state_reg.read((bit<32>)target_port);
        stage_state_reg.write((bit<32>)target_port, prev_state + 1);
    }

    action drop_ipv4lpmengine_stage1(bit<8> drop_code) {
        ig_to_eg_md.drop_flag = 1#1;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_DROP;
    }

    table ipv4lpmengine_stage1_table {
        key = {
            ig_intr_md.ingress_port:           exact;
            user_meta.l2_meta.ingress_vlan_id: ternary;
            hdr.ipv4.dst_addr:                 ternary;
            hdr.ipv4.src_addr:                 ternary;
            hdr.ipv4.protocol:                 ternary;
            user_meta.parser_meta.l4_src_port: ternary;
            user_meta.parser_meta.l4_dst_port: ternary;
        }
        actions = {
            execute_ipv4lpmengine_stage1_act0;
            execute_ipv4lpmengine_stage1_act1;
            execute_ipv4lpmengine_stage1_act2;
            execute_ipv4lpmengine_stage1_act3;
            drop_ipv4lpmengine_stage1;
            NoAction;
        }
        size = 2048;
        default_action = NoAction();
    }

    apply {
        ipv4lpmengine_stage1_table.apply();
    }
}

control ChockIpv4LpmEngineStage2(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    ChockRegister<bit<32>>(2048, 0) stage_state_reg;
    ChockCounter(2048, CounterType_t.PACKETS_AND_BYTES) stage_counter;
    ChockMeter(2048) stage_meter;

    action execute_ipv4lpmengine_stage2_act0(
        port_id_t  target_port,
        bit<16>    flow_metric,
        bit<8>     qos_class,
        mac_addr_t rewrite_mac
    ) {
        ig_to_eg_md.egress_port = target_port;
        ig_to_eg_md.traffic_class = qos_class[2:0];
        user_meta.l3_meta.route_metric = flow_metric;
        stage_counter.count((bit<32>)target_port);
        bit<32> prev_state = stage_state_reg.read((bit<32>)target_port);
        stage_state_reg.write((bit<32>)target_port, prev_state + 1);
    }

    action execute_ipv4lpmengine_stage2_act1(
        port_id_t  target_port,
        bit<16>    flow_metric,
        bit<8>     qos_class,
        mac_addr_t rewrite_mac
    ) {
        ig_to_eg_md.egress_port = target_port;
        ig_to_eg_md.traffic_class = qos_class[2:0];
        user_meta.l3_meta.route_metric = flow_metric;
        stage_counter.count((bit<32>)target_port);
        bit<32> prev_state = stage_state_reg.read((bit<32>)target_port);
        stage_state_reg.write((bit<32>)target_port, prev_state + 1);
    }

    action execute_ipv4lpmengine_stage2_act2(
        port_id_t  target_port,
        bit<16>    flow_metric,
        bit<8>     qos_class,
        mac_addr_t rewrite_mac
    ) {
        ig_to_eg_md.egress_port = target_port;
        ig_to_eg_md.traffic_class = qos_class[2:0];
        user_meta.l3_meta.route_metric = flow_metric;
        stage_counter.count((bit<32>)target_port);
        bit<32> prev_state = stage_state_reg.read((bit<32>)target_port);
        stage_state_reg.write((bit<32>)target_port, prev_state + 1);
    }

    action execute_ipv4lpmengine_stage2_act3(
        port_id_t  target_port,
        bit<16>    flow_metric,
        bit<8>     qos_class,
        mac_addr_t rewrite_mac
    ) {
        ig_to_eg_md.egress_port = target_port;
        ig_to_eg_md.traffic_class = qos_class[2:0];
        user_meta.l3_meta.route_metric = flow_metric;
        stage_counter.count((bit<32>)target_port);
        bit<32> prev_state = stage_state_reg.read((bit<32>)target_port);
        stage_state_reg.write((bit<32>)target_port, prev_state + 1);
    }

    action drop_ipv4lpmengine_stage2(bit<8> drop_code) {
        ig_to_eg_md.drop_flag = 1#1;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_DROP;
    }

    table ipv4lpmengine_stage2_table {
        key = {
            ig_intr_md.ingress_port:           exact;
            user_meta.l2_meta.ingress_vlan_id: ternary;
            hdr.ipv4.dst_addr:                 ternary;
            hdr.ipv4.src_addr:                 ternary;
            hdr.ipv4.protocol:                 ternary;
            user_meta.parser_meta.l4_src_port: ternary;
            user_meta.parser_meta.l4_dst_port: ternary;
        }
        actions = {
            execute_ipv4lpmengine_stage2_act0;
            execute_ipv4lpmengine_stage2_act1;
            execute_ipv4lpmengine_stage2_act2;
            execute_ipv4lpmengine_stage2_act3;
            drop_ipv4lpmengine_stage2;
            NoAction;
        }
        size = 2048;
        default_action = NoAction();
    }

    apply {
        ipv4lpmengine_stage2_table.apply();
    }
}

control ChockIpv4LpmEngineStage3(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    ChockRegister<bit<32>>(2048, 0) stage_state_reg;
    ChockCounter(2048, CounterType_t.PACKETS_AND_BYTES) stage_counter;
    ChockMeter(2048) stage_meter;

    action execute_ipv4lpmengine_stage3_act0(
        port_id_t  target_port,
        bit<16>    flow_metric,
        bit<8>     qos_class,
        mac_addr_t rewrite_mac
    ) {
        ig_to_eg_md.egress_port = target_port;
        ig_to_eg_md.traffic_class = qos_class[2:0];
        user_meta.l3_meta.route_metric = flow_metric;
        stage_counter.count((bit<32>)target_port);
        bit<32> prev_state = stage_state_reg.read((bit<32>)target_port);
        stage_state_reg.write((bit<32>)target_port, prev_state + 1);
    }

    action execute_ipv4lpmengine_stage3_act1(
        port_id_t  target_port,
        bit<16>    flow_metric,
        bit<8>     qos_class,
        mac_addr_t rewrite_mac
    ) {
        ig_to_eg_md.egress_port = target_port;
        ig_to_eg_md.traffic_class = qos_class[2:0];
        user_meta.l3_meta.route_metric = flow_metric;
        stage_counter.count((bit<32>)target_port);
        bit<32> prev_state = stage_state_reg.read((bit<32>)target_port);
        stage_state_reg.write((bit<32>)target_port, prev_state + 1);
    }

    action execute_ipv4lpmengine_stage3_act2(
        port_id_t  target_port,
        bit<16>    flow_metric,
        bit<8>     qos_class,
        mac_addr_t rewrite_mac
    ) {
        ig_to_eg_md.egress_port = target_port;
        ig_to_eg_md.traffic_class = qos_class[2:0];
        user_meta.l3_meta.route_metric = flow_metric;
        stage_counter.count((bit<32>)target_port);
        bit<32> prev_state = stage_state_reg.read((bit<32>)target_port);
        stage_state_reg.write((bit<32>)target_port, prev_state + 1);
    }

    action execute_ipv4lpmengine_stage3_act3(
        port_id_t  target_port,
        bit<16>    flow_metric,
        bit<8>     qos_class,
        mac_addr_t rewrite_mac
    ) {
        ig_to_eg_md.egress_port = target_port;
        ig_to_eg_md.traffic_class = qos_class[2:0];
        user_meta.l3_meta.route_metric = flow_metric;
        stage_counter.count((bit<32>)target_port);
        bit<32> prev_state = stage_state_reg.read((bit<32>)target_port);
        stage_state_reg.write((bit<32>)target_port, prev_state + 1);
    }

    action drop_ipv4lpmengine_stage3(bit<8> drop_code) {
        ig_to_eg_md.drop_flag = 1#1;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_DROP;
    }

    table ipv4lpmengine_stage3_table {
        key = {
            ig_intr_md.ingress_port:           exact;
            user_meta.l2_meta.ingress_vlan_id: ternary;
            hdr.ipv4.dst_addr:                 ternary;
            hdr.ipv4.src_addr:                 ternary;
            hdr.ipv4.protocol:                 ternary;
            user_meta.parser_meta.l4_src_port: ternary;
            user_meta.parser_meta.l4_dst_port: ternary;
        }
        actions = {
            execute_ipv4lpmengine_stage3_act0;
            execute_ipv4lpmengine_stage3_act1;
            execute_ipv4lpmengine_stage3_act2;
            execute_ipv4lpmengine_stage3_act3;
            drop_ipv4lpmengine_stage3;
            NoAction;
        }
        size = 2048;
        default_action = NoAction();
    }

    apply {
        ipv4lpmengine_stage3_table.apply();
    }
}

control ChockIpv4LpmEngineStage4(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    ChockRegister<bit<32>>(2048, 0) stage_state_reg;
    ChockCounter(2048, CounterType_t.PACKETS_AND_BYTES) stage_counter;
    ChockMeter(2048) stage_meter;

    action execute_ipv4lpmengine_stage4_act0(
        port_id_t  target_port,
        bit<16>    flow_metric,
        bit<8>     qos_class,
        mac_addr_t rewrite_mac
    ) {
        ig_to_eg_md.egress_port = target_port;
        ig_to_eg_md.traffic_class = qos_class[2:0];
        user_meta.l3_meta.route_metric = flow_metric;
        stage_counter.count((bit<32>)target_port);
        bit<32> prev_state = stage_state_reg.read((bit<32>)target_port);
        stage_state_reg.write((bit<32>)target_port, prev_state + 1);
    }

    action execute_ipv4lpmengine_stage4_act1(
        port_id_t  target_port,
        bit<16>    flow_metric,
        bit<8>     qos_class,
        mac_addr_t rewrite_mac
    ) {
        ig_to_eg_md.egress_port = target_port;
        ig_to_eg_md.traffic_class = qos_class[2:0];
        user_meta.l3_meta.route_metric = flow_metric;
        stage_counter.count((bit<32>)target_port);
        bit<32> prev_state = stage_state_reg.read((bit<32>)target_port);
        stage_state_reg.write((bit<32>)target_port, prev_state + 1);
    }

    action execute_ipv4lpmengine_stage4_act2(
        port_id_t  target_port,
        bit<16>    flow_metric,
        bit<8>     qos_class,
        mac_addr_t rewrite_mac
    ) {
        ig_to_eg_md.egress_port = target_port;
        ig_to_eg_md.traffic_class = qos_class[2:0];
        user_meta.l3_meta.route_metric = flow_metric;
        stage_counter.count((bit<32>)target_port);
        bit<32> prev_state = stage_state_reg.read((bit<32>)target_port);
        stage_state_reg.write((bit<32>)target_port, prev_state + 1);
    }

    action execute_ipv4lpmengine_stage4_act3(
        port_id_t  target_port,
        bit<16>    flow_metric,
        bit<8>     qos_class,
        mac_addr_t rewrite_mac
    ) {
        ig_to_eg_md.egress_port = target_port;
        ig_to_eg_md.traffic_class = qos_class[2:0];
        user_meta.l3_meta.route_metric = flow_metric;
        stage_counter.count((bit<32>)target_port);
        bit<32> prev_state = stage_state_reg.read((bit<32>)target_port);
        stage_state_reg.write((bit<32>)target_port, prev_state + 1);
    }

    action drop_ipv4lpmengine_stage4(bit<8> drop_code) {
        ig_to_eg_md.drop_flag = 1#1;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_DROP;
    }

    table ipv4lpmengine_stage4_table {
        key = {
            ig_intr_md.ingress_port:           exact;
            user_meta.l2_meta.ingress_vlan_id: ternary;
            hdr.ipv4.dst_addr:                 ternary;
            hdr.ipv4.src_addr:                 ternary;
            hdr.ipv4.protocol:                 ternary;
            user_meta.parser_meta.l4_src_port: ternary;
            user_meta.parser_meta.l4_dst_port: ternary;
        }
        actions = {
            execute_ipv4lpmengine_stage4_act0;
            execute_ipv4lpmengine_stage4_act1;
            execute_ipv4lpmengine_stage4_act2;
            execute_ipv4lpmengine_stage4_act3;
            drop_ipv4lpmengine_stage4;
            NoAction;
        }
        size = 2048;
        default_action = NoAction();
    }

    apply {
        ipv4lpmengine_stage4_table.apply();
    }
}

control ChockIpv4LpmEngineStage5(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    ChockRegister<bit<32>>(2048, 0) stage_state_reg;
    ChockCounter(2048, CounterType_t.PACKETS_AND_BYTES) stage_counter;
    ChockMeter(2048) stage_meter;

    action execute_ipv4lpmengine_stage5_act0(
        port_id_t  target_port,
        bit<16>    flow_metric,
        bit<8>     qos_class,
        mac_addr_t rewrite_mac
    ) {
        ig_to_eg_md.egress_port = target_port;
        ig_to_eg_md.traffic_class = qos_class[2:0];
        user_meta.l3_meta.route_metric = flow_metric;
        stage_counter.count((bit<32>)target_port);
        bit<32> prev_state = stage_state_reg.read((bit<32>)target_port);
        stage_state_reg.write((bit<32>)target_port, prev_state + 1);
    }

    action execute_ipv4lpmengine_stage5_act1(
        port_id_t  target_port,
        bit<16>    flow_metric,
        bit<8>     qos_class,
        mac_addr_t rewrite_mac
    ) {
        ig_to_eg_md.egress_port = target_port;
        ig_to_eg_md.traffic_class = qos_class[2:0];
        user_meta.l3_meta.route_metric = flow_metric;
        stage_counter.count((bit<32>)target_port);
        bit<32> prev_state = stage_state_reg.read((bit<32>)target_port);
        stage_state_reg.write((bit<32>)target_port, prev_state + 1);
    }

    action execute_ipv4lpmengine_stage5_act2(
        port_id_t  target_port,
        bit<16>    flow_metric,
        bit<8>     qos_class,
        mac_addr_t rewrite_mac
    ) {
        ig_to_eg_md.egress_port = target_port;
        ig_to_eg_md.traffic_class = qos_class[2:0];
        user_meta.l3_meta.route_metric = flow_metric;
        stage_counter.count((bit<32>)target_port);
        bit<32> prev_state = stage_state_reg.read((bit<32>)target_port);
        stage_state_reg.write((bit<32>)target_port, prev_state + 1);
    }

    action execute_ipv4lpmengine_stage5_act3(
        port_id_t  target_port,
        bit<16>    flow_metric,
        bit<8>     qos_class,
        mac_addr_t rewrite_mac
    ) {
        ig_to_eg_md.egress_port = target_port;
        ig_to_eg_md.traffic_class = qos_class[2:0];
        user_meta.l3_meta.route_metric = flow_metric;
        stage_counter.count((bit<32>)target_port);
        bit<32> prev_state = stage_state_reg.read((bit<32>)target_port);
        stage_state_reg.write((bit<32>)target_port, prev_state + 1);
    }

    action drop_ipv4lpmengine_stage5(bit<8> drop_code) {
        ig_to_eg_md.drop_flag = 1#1;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_DROP;
    }

    table ipv4lpmengine_stage5_table {
        key = {
            ig_intr_md.ingress_port:           exact;
            user_meta.l2_meta.ingress_vlan_id: ternary;
            hdr.ipv4.dst_addr:                 ternary;
            hdr.ipv4.src_addr:                 ternary;
            hdr.ipv4.protocol:                 ternary;
            user_meta.parser_meta.l4_src_port: ternary;
            user_meta.parser_meta.l4_dst_port: ternary;
        }
        actions = {
            execute_ipv4lpmengine_stage5_act0;
            execute_ipv4lpmengine_stage5_act1;
            execute_ipv4lpmengine_stage5_act2;
            execute_ipv4lpmengine_stage5_act3;
            drop_ipv4lpmengine_stage5;
            NoAction;
        }
        size = 2048;
        default_action = NoAction();
    }

    apply {
        ipv4lpmengine_stage5_table.apply();
    }
}

control ChockIpv4LpmEngineStage6(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    ChockRegister<bit<32>>(2048, 0) stage_state_reg;
    ChockCounter(2048, CounterType_t.PACKETS_AND_BYTES) stage_counter;
    ChockMeter(2048) stage_meter;

    action execute_ipv4lpmengine_stage6_act0(
        port_id_t  target_port,
        bit<16>    flow_metric,
        bit<8>     qos_class,
        mac_addr_t rewrite_mac
    ) {
        ig_to_eg_md.egress_port = target_port;
        ig_to_eg_md.traffic_class = qos_class[2:0];
        user_meta.l3_meta.route_metric = flow_metric;
        stage_counter.count((bit<32>)target_port);
        bit<32> prev_state = stage_state_reg.read((bit<32>)target_port);
        stage_state_reg.write((bit<32>)target_port, prev_state + 1);
    }

    action execute_ipv4lpmengine_stage6_act1(
        port_id_t  target_port,
        bit<16>    flow_metric,
        bit<8>     qos_class,
        mac_addr_t rewrite_mac
    ) {
        ig_to_eg_md.egress_port = target_port;
        ig_to_eg_md.traffic_class = qos_class[2:0];
        user_meta.l3_meta.route_metric = flow_metric;
        stage_counter.count((bit<32>)target_port);
        bit<32> prev_state = stage_state_reg.read((bit<32>)target_port);
        stage_state_reg.write((bit<32>)target_port, prev_state + 1);
    }

    action execute_ipv4lpmengine_stage6_act2(
        port_id_t  target_port,
        bit<16>    flow_metric,
        bit<8>     qos_class,
        mac_addr_t rewrite_mac
    ) {
        ig_to_eg_md.egress_port = target_port;
        ig_to_eg_md.traffic_class = qos_class[2:0];
        user_meta.l3_meta.route_metric = flow_metric;
        stage_counter.count((bit<32>)target_port);
        bit<32> prev_state = stage_state_reg.read((bit<32>)target_port);
        stage_state_reg.write((bit<32>)target_port, prev_state + 1);
    }

    action execute_ipv4lpmengine_stage6_act3(
        port_id_t  target_port,
        bit<16>    flow_metric,
        bit<8>     qos_class,
        mac_addr_t rewrite_mac
    ) {
        ig_to_eg_md.egress_port = target_port;
        ig_to_eg_md.traffic_class = qos_class[2:0];
        user_meta.l3_meta.route_metric = flow_metric;
        stage_counter.count((bit<32>)target_port);
        bit<32> prev_state = stage_state_reg.read((bit<32>)target_port);
        stage_state_reg.write((bit<32>)target_port, prev_state + 1);
    }

    action drop_ipv4lpmengine_stage6(bit<8> drop_code) {
        ig_to_eg_md.drop_flag = 1#1;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_DROP;
    }

    table ipv4lpmengine_stage6_table {
        key = {
            ig_intr_md.ingress_port:           exact;
            user_meta.l2_meta.ingress_vlan_id: ternary;
            hdr.ipv4.dst_addr:                 ternary;
            hdr.ipv4.src_addr:                 ternary;
            hdr.ipv4.protocol:                 ternary;
            user_meta.parser_meta.l4_src_port: ternary;
            user_meta.parser_meta.l4_dst_port: ternary;
        }
        actions = {
            execute_ipv4lpmengine_stage6_act0;
            execute_ipv4lpmengine_stage6_act1;
            execute_ipv4lpmengine_stage6_act2;
            execute_ipv4lpmengine_stage6_act3;
            drop_ipv4lpmengine_stage6;
            NoAction;
        }
        size = 2048;
        default_action = NoAction();
    }

    apply {
        ipv4lpmengine_stage6_table.apply();
    }
}

control ChockIpv4LpmEngineStage7(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    ChockRegister<bit<32>>(2048, 0) stage_state_reg;
    ChockCounter(2048, CounterType_t.PACKETS_AND_BYTES) stage_counter;
    ChockMeter(2048) stage_meter;

    action execute_ipv4lpmengine_stage7_act0(
        port_id_t  target_port,
        bit<16>    flow_metric,
        bit<8>     qos_class,
        mac_addr_t rewrite_mac
    ) {
        ig_to_eg_md.egress_port = target_port;
        ig_to_eg_md.traffic_class = qos_class[2:0];
        user_meta.l3_meta.route_metric = flow_metric;
        stage_counter.count((bit<32>)target_port);
        bit<32> prev_state = stage_state_reg.read((bit<32>)target_port);
        stage_state_reg.write((bit<32>)target_port, prev_state + 1);
    }

    action execute_ipv4lpmengine_stage7_act1(
        port_id_t  target_port,
        bit<16>    flow_metric,
        bit<8>     qos_class,
        mac_addr_t rewrite_mac
    ) {
        ig_to_eg_md.egress_port = target_port;
        ig_to_eg_md.traffic_class = qos_class[2:0];
        user_meta.l3_meta.route_metric = flow_metric;
        stage_counter.count((bit<32>)target_port);
        bit<32> prev_state = stage_state_reg.read((bit<32>)target_port);
        stage_state_reg.write((bit<32>)target_port, prev_state + 1);
    }

    action execute_ipv4lpmengine_stage7_act2(
        port_id_t  target_port,
        bit<16>    flow_metric,
        bit<8>     qos_class,
        mac_addr_t rewrite_mac
    ) {
        ig_to_eg_md.egress_port = target_port;
        ig_to_eg_md.traffic_class = qos_class[2:0];
        user_meta.l3_meta.route_metric = flow_metric;
        stage_counter.count((bit<32>)target_port);
        bit<32> prev_state = stage_state_reg.read((bit<32>)target_port);
        stage_state_reg.write((bit<32>)target_port, prev_state + 1);
    }

    action execute_ipv4lpmengine_stage7_act3(
        port_id_t  target_port,
        bit<16>    flow_metric,
        bit<8>     qos_class,
        mac_addr_t rewrite_mac
    ) {
        ig_to_eg_md.egress_port = target_port;
        ig_to_eg_md.traffic_class = qos_class[2:0];
        user_meta.l3_meta.route_metric = flow_metric;
        stage_counter.count((bit<32>)target_port);
        bit<32> prev_state = stage_state_reg.read((bit<32>)target_port);
        stage_state_reg.write((bit<32>)target_port, prev_state + 1);
    }

    action drop_ipv4lpmengine_stage7(bit<8> drop_code) {
        ig_to_eg_md.drop_flag = 1#1;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_DROP;
    }

    table ipv4lpmengine_stage7_table {
        key = {
            ig_intr_md.ingress_port:           exact;
            user_meta.l2_meta.ingress_vlan_id: ternary;
            hdr.ipv4.dst_addr:                 ternary;
            hdr.ipv4.src_addr:                 ternary;
            hdr.ipv4.protocol:                 ternary;
            user_meta.parser_meta.l4_src_port: ternary;
            user_meta.parser_meta.l4_dst_port: ternary;
        }
        actions = {
            execute_ipv4lpmengine_stage7_act0;
            execute_ipv4lpmengine_stage7_act1;
            execute_ipv4lpmengine_stage7_act2;
            execute_ipv4lpmengine_stage7_act3;
            drop_ipv4lpmengine_stage7;
            NoAction;
        }
        size = 2048;
        default_action = NoAction();
    }

    apply {
        ipv4lpmengine_stage7_table.apply();
    }
}

control ChockIpv4LpmEngineStage8(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    ChockRegister<bit<32>>(2048, 0) stage_state_reg;
    ChockCounter(2048, CounterType_t.PACKETS_AND_BYTES) stage_counter;
    ChockMeter(2048) stage_meter;

    action execute_ipv4lpmengine_stage8_act0(
        port_id_t  target_port,
        bit<16>    flow_metric,
        bit<8>     qos_class,
        mac_addr_t rewrite_mac
    ) {
        ig_to_eg_md.egress_port = target_port;
        ig_to_eg_md.traffic_class = qos_class[2:0];
        user_meta.l3_meta.route_metric = flow_metric;
        stage_counter.count((bit<32>)target_port);
        bit<32> prev_state = stage_state_reg.read((bit<32>)target_port);
        stage_state_reg.write((bit<32>)target_port, prev_state + 1);
    }

    action execute_ipv4lpmengine_stage8_act1(
        port_id_t  target_port,
        bit<16>    flow_metric,
        bit<8>     qos_class,
        mac_addr_t rewrite_mac
    ) {
        ig_to_eg_md.egress_port = target_port;
        ig_to_eg_md.traffic_class = qos_class[2:0];
        user_meta.l3_meta.route_metric = flow_metric;
        stage_counter.count((bit<32>)target_port);
        bit<32> prev_state = stage_state_reg.read((bit<32>)target_port);
        stage_state_reg.write((bit<32>)target_port, prev_state + 1);
    }

    action execute_ipv4lpmengine_stage8_act2(
        port_id_t  target_port,
        bit<16>    flow_metric,
        bit<8>     qos_class,
        mac_addr_t rewrite_mac
    ) {
        ig_to_eg_md.egress_port = target_port;
        ig_to_eg_md.traffic_class = qos_class[2:0];
        user_meta.l3_meta.route_metric = flow_metric;
        stage_counter.count((bit<32>)target_port);
        bit<32> prev_state = stage_state_reg.read((bit<32>)target_port);
        stage_state_reg.write((bit<32>)target_port, prev_state + 1);
    }

    action execute_ipv4lpmengine_stage8_act3(
        port_id_t  target_port,
        bit<16>    flow_metric,
        bit<8>     qos_class,
        mac_addr_t rewrite_mac
    ) {
        ig_to_eg_md.egress_port = target_port;
        ig_to_eg_md.traffic_class = qos_class[2:0];
        user_meta.l3_meta.route_metric = flow_metric;
        stage_counter.count((bit<32>)target_port);
        bit<32> prev_state = stage_state_reg.read((bit<32>)target_port);
        stage_state_reg.write((bit<32>)target_port, prev_state + 1);
    }

    action drop_ipv4lpmengine_stage8(bit<8> drop_code) {
        ig_to_eg_md.drop_flag = 1#1;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_DROP;
    }

    table ipv4lpmengine_stage8_table {
        key = {
            ig_intr_md.ingress_port:           exact;
            user_meta.l2_meta.ingress_vlan_id: ternary;
            hdr.ipv4.dst_addr:                 ternary;
            hdr.ipv4.src_addr:                 ternary;
            hdr.ipv4.protocol:                 ternary;
            user_meta.parser_meta.l4_src_port: ternary;
            user_meta.parser_meta.l4_dst_port: ternary;
        }
        actions = {
            execute_ipv4lpmengine_stage8_act0;
            execute_ipv4lpmengine_stage8_act1;
            execute_ipv4lpmengine_stage8_act2;
            execute_ipv4lpmengine_stage8_act3;
            drop_ipv4lpmengine_stage8;
            NoAction;
        }
        size = 2048;
        default_action = NoAction();
    }

    apply {
        ipv4lpmengine_stage8_table.apply();
    }
}

control ChockIpv4LpmEngineStage9(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    ChockRegister<bit<32>>(2048, 0) stage_state_reg;
    ChockCounter(2048, CounterType_t.PACKETS_AND_BYTES) stage_counter;
    ChockMeter(2048) stage_meter;

    action execute_ipv4lpmengine_stage9_act0(
        port_id_t  target_port,
        bit<16>    flow_metric,
        bit<8>     qos_class,
        mac_addr_t rewrite_mac
    ) {
        ig_to_eg_md.egress_port = target_port;
        ig_to_eg_md.traffic_class = qos_class[2:0];
        user_meta.l3_meta.route_metric = flow_metric;
        stage_counter.count((bit<32>)target_port);
        bit<32> prev_state = stage_state_reg.read((bit<32>)target_port);
        stage_state_reg.write((bit<32>)target_port, prev_state + 1);
    }

    action execute_ipv4lpmengine_stage9_act1(
        port_id_t  target_port,
        bit<16>    flow_metric,
        bit<8>     qos_class,
        mac_addr_t rewrite_mac
    ) {
        ig_to_eg_md.egress_port = target_port;
        ig_to_eg_md.traffic_class = qos_class[2:0];
        user_meta.l3_meta.route_metric = flow_metric;
        stage_counter.count((bit<32>)target_port);
        bit<32> prev_state = stage_state_reg.read((bit<32>)target_port);
        stage_state_reg.write((bit<32>)target_port, prev_state + 1);
    }

    action execute_ipv4lpmengine_stage9_act2(
        port_id_t  target_port,
        bit<16>    flow_metric,
        bit<8>     qos_class,
        mac_addr_t rewrite_mac
    ) {
        ig_to_eg_md.egress_port = target_port;
        ig_to_eg_md.traffic_class = qos_class[2:0];
        user_meta.l3_meta.route_metric = flow_metric;
        stage_counter.count((bit<32>)target_port);
        bit<32> prev_state = stage_state_reg.read((bit<32>)target_port);
        stage_state_reg.write((bit<32>)target_port, prev_state + 1);
    }

    action execute_ipv4lpmengine_stage9_act3(
        port_id_t  target_port,
        bit<16>    flow_metric,
        bit<8>     qos_class,
        mac_addr_t rewrite_mac
    ) {
        ig_to_eg_md.egress_port = target_port;
        ig_to_eg_md.traffic_class = qos_class[2:0];
        user_meta.l3_meta.route_metric = flow_metric;
        stage_counter.count((bit<32>)target_port);
        bit<32> prev_state = stage_state_reg.read((bit<32>)target_port);
        stage_state_reg.write((bit<32>)target_port, prev_state + 1);
    }

    action drop_ipv4lpmengine_stage9(bit<8> drop_code) {
        ig_to_eg_md.drop_flag = 1#1;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_DROP;
    }

    table ipv4lpmengine_stage9_table {
        key = {
            ig_intr_md.ingress_port:           exact;
            user_meta.l2_meta.ingress_vlan_id: ternary;
            hdr.ipv4.dst_addr:                 ternary;
            hdr.ipv4.src_addr:                 ternary;
            hdr.ipv4.protocol:                 ternary;
            user_meta.parser_meta.l4_src_port: ternary;
            user_meta.parser_meta.l4_dst_port: ternary;
        }
        actions = {
            execute_ipv4lpmengine_stage9_act0;
            execute_ipv4lpmengine_stage9_act1;
            execute_ipv4lpmengine_stage9_act2;
            execute_ipv4lpmengine_stage9_act3;
            drop_ipv4lpmengine_stage9;
            NoAction;
        }
        size = 2048;
        default_action = NoAction();
    }

    apply {
        ipv4lpmengine_stage9_table.apply();
    }
}

control ChockIpv4LpmEngineStage10(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    ChockRegister<bit<32>>(2048, 0) stage_state_reg;
    ChockCounter(2048, CounterType_t.PACKETS_AND_BYTES) stage_counter;
    ChockMeter(2048) stage_meter;

    action execute_ipv4lpmengine_stage10_act0(
        port_id_t  target_port,
        bit<16>    flow_metric,
        bit<8>     qos_class,
        mac_addr_t rewrite_mac
    ) {
        ig_to_eg_md.egress_port = target_port;
        ig_to_eg_md.traffic_class = qos_class[2:0];
        user_meta.l3_meta.route_metric = flow_metric;
        stage_counter.count((bit<32>)target_port);
        bit<32> prev_state = stage_state_reg.read((bit<32>)target_port);
        stage_state_reg.write((bit<32>)target_port, prev_state + 1);
    }

    action execute_ipv4lpmengine_stage10_act1(
        port_id_t  target_port,
        bit<16>    flow_metric,
        bit<8>     qos_class,
        mac_addr_t rewrite_mac
    ) {
        ig_to_eg_md.egress_port = target_port;
        ig_to_eg_md.traffic_class = qos_class[2:0];
        user_meta.l3_meta.route_metric = flow_metric;
        stage_counter.count((bit<32>)target_port);
        bit<32> prev_state = stage_state_reg.read((bit<32>)target_port);
        stage_state_reg.write((bit<32>)target_port, prev_state + 1);
    }

    action execute_ipv4lpmengine_stage10_act2(
        port_id_t  target_port,
        bit<16>    flow_metric,
        bit<8>     qos_class,
        mac_addr_t rewrite_mac
    ) {
        ig_to_eg_md.egress_port = target_port;
        ig_to_eg_md.traffic_class = qos_class[2:0];
        user_meta.l3_meta.route_metric = flow_metric;
        stage_counter.count((bit<32>)target_port);
        bit<32> prev_state = stage_state_reg.read((bit<32>)target_port);
        stage_state_reg.write((bit<32>)target_port, prev_state + 1);
    }

    action execute_ipv4lpmengine_stage10_act3(
        port_id_t  target_port,
        bit<16>    flow_metric,
        bit<8>     qos_class,
        mac_addr_t rewrite_mac
    ) {
        ig_to_eg_md.egress_port = target_port;
        ig_to_eg_md.traffic_class = qos_class[2:0];
        user_meta.l3_meta.route_metric = flow_metric;
        stage_counter.count((bit<32>)target_port);
        bit<32> prev_state = stage_state_reg.read((bit<32>)target_port);
        stage_state_reg.write((bit<32>)target_port, prev_state + 1);
    }

    action drop_ipv4lpmengine_stage10(bit<8> drop_code) {
        ig_to_eg_md.drop_flag = 1#1;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_DROP;
    }

    table ipv4lpmengine_stage10_table {
        key = {
            ig_intr_md.ingress_port:           exact;
            user_meta.l2_meta.ingress_vlan_id: ternary;
            hdr.ipv4.dst_addr:                 ternary;
            hdr.ipv4.src_addr:                 ternary;
            hdr.ipv4.protocol:                 ternary;
            user_meta.parser_meta.l4_src_port: ternary;
            user_meta.parser_meta.l4_dst_port: ternary;
        }
        actions = {
            execute_ipv4lpmengine_stage10_act0;
            execute_ipv4lpmengine_stage10_act1;
            execute_ipv4lpmengine_stage10_act2;
            execute_ipv4lpmengine_stage10_act3;
            drop_ipv4lpmengine_stage10;
            NoAction;
        }
        size = 2048;
        default_action = NoAction();
    }

    apply {
        ipv4lpmengine_stage10_table.apply();
    }
}

control ChockIpv4LpmEngineStage11(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    ChockRegister<bit<32>>(2048, 0) stage_state_reg;
    ChockCounter(2048, CounterType_t.PACKETS_AND_BYTES) stage_counter;
    ChockMeter(2048) stage_meter;

    action execute_ipv4lpmengine_stage11_act0(
        port_id_t  target_port,
        bit<16>    flow_metric,
        bit<8>     qos_class,
        mac_addr_t rewrite_mac
    ) {
        ig_to_eg_md.egress_port = target_port;
        ig_to_eg_md.traffic_class = qos_class[2:0];
        user_meta.l3_meta.route_metric = flow_metric;
        stage_counter.count((bit<32>)target_port);
        bit<32> prev_state = stage_state_reg.read((bit<32>)target_port);
        stage_state_reg.write((bit<32>)target_port, prev_state + 1);
    }

    action execute_ipv4lpmengine_stage11_act1(
        port_id_t  target_port,
        bit<16>    flow_metric,
        bit<8>     qos_class,
        mac_addr_t rewrite_mac
    ) {
        ig_to_eg_md.egress_port = target_port;
        ig_to_eg_md.traffic_class = qos_class[2:0];
        user_meta.l3_meta.route_metric = flow_metric;
        stage_counter.count((bit<32>)target_port);
        bit<32> prev_state = stage_state_reg.read((bit<32>)target_port);
        stage_state_reg.write((bit<32>)target_port, prev_state + 1);
    }

    action execute_ipv4lpmengine_stage11_act2(
        port_id_t  target_port,
        bit<16>    flow_metric,
        bit<8>     qos_class,
        mac_addr_t rewrite_mac
    ) {
        ig_to_eg_md.egress_port = target_port;
        ig_to_eg_md.traffic_class = qos_class[2:0];
        user_meta.l3_meta.route_metric = flow_metric;
        stage_counter.count((bit<32>)target_port);
        bit<32> prev_state = stage_state_reg.read((bit<32>)target_port);
        stage_state_reg.write((bit<32>)target_port, prev_state + 1);
    }

    action execute_ipv4lpmengine_stage11_act3(
        port_id_t  target_port,
        bit<16>    flow_metric,
        bit<8>     qos_class,
        mac_addr_t rewrite_mac
    ) {
        ig_to_eg_md.egress_port = target_port;
        ig_to_eg_md.traffic_class = qos_class[2:0];
        user_meta.l3_meta.route_metric = flow_metric;
        stage_counter.count((bit<32>)target_port);
        bit<32> prev_state = stage_state_reg.read((bit<32>)target_port);
        stage_state_reg.write((bit<32>)target_port, prev_state + 1);
    }

    action drop_ipv4lpmengine_stage11(bit<8> drop_code) {
        ig_to_eg_md.drop_flag = 1#1;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_DROP;
    }

    table ipv4lpmengine_stage11_table {
        key = {
            ig_intr_md.ingress_port:           exact;
            user_meta.l2_meta.ingress_vlan_id: ternary;
            hdr.ipv4.dst_addr:                 ternary;
            hdr.ipv4.src_addr:                 ternary;
            hdr.ipv4.protocol:                 ternary;
            user_meta.parser_meta.l4_src_port: ternary;
            user_meta.parser_meta.l4_dst_port: ternary;
        }
        actions = {
            execute_ipv4lpmengine_stage11_act0;
            execute_ipv4lpmengine_stage11_act1;
            execute_ipv4lpmengine_stage11_act2;
            execute_ipv4lpmengine_stage11_act3;
            drop_ipv4lpmengine_stage11;
            NoAction;
        }
        size = 2048;
        default_action = NoAction();
    }

    apply {
        ipv4lpmengine_stage11_table.apply();
    }
}

#endif /* _CHOCK_ROUTING_IPV4_LPM_P4_ */
