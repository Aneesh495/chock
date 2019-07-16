/*
 * Autonomous Data Plane ICMP Error and Echo Synthesis (P4_16)
 *
 * Synthesizes ICMP Echo Reply, ICMP Time Exceeded (TTL expired in transit),
 * and Destination Unreachable messages directly within the forwarding pipeline.
 */

#ifndef _CHOCK_PROTOCOLS_ICMP_GENERATOR_P4_
#define _CHOCK_PROTOCOLS_ICMP_GENERATOR_P4_

#include "../arch/chock_arch.p4"
#include "../core/types.p4"
#include "../core/unified_headers.p4"
#include "../core/metadata.p4"

control ChockIcmpGenerator(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    action generate_echo_reply() {
        hdr.icmpv4.msg_type = ICMPV4_TYPE_ECHO_REPLY;
        hdr.icmpv4.msg_code = 8#00;
        hdr.icmpv4.checksum = hdr.icmpv4.checksum + 16#0800;

        ipv4_addr_t tmp_ip = hdr.ipv4.src_addr;
        hdr.ipv4.src_addr = hdr.ipv4.dst_addr;
        hdr.ipv4.dst_addr = tmp_ip;
        hdr.ipv4.ttl = 64;

        mac_addr_t tmp_mac = hdr.ethernet.src_addr;
        hdr.ethernet.src_addr = hdr.ethernet.dst_addr;
        hdr.ethernet.dst_addr = tmp_mac;

        ig_to_eg_md.egress_port = ig_intr_md.ingress_port;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_UNICAST;
    }

    apply {
        if (hdr.icmpv4.isValid() && hdr.icmpv4.msg_type == ICMPV4_TYPE_ECHO_REQUEST) {
            generate_echo_reply();
        }
    }
}


/*
 * Comprehensive Match-Action Processing Pipeline for IcmpGeneratorEngine
 * Implements hardware TCAM, SRAM, and stateful ALU execution stages.
 */

control ChockIcmpGeneratorEngineStage0(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    ChockRegister<bit<32>>(2048, 0) stage_state_reg;
    ChockCounter(2048, CounterType_t.PACKETS_AND_BYTES) stage_counter;
    ChockMeter(2048) stage_meter;

    action execute_icmpgeneratorengine_stage0_act0(
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

    action execute_icmpgeneratorengine_stage0_act1(
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

    action execute_icmpgeneratorengine_stage0_act2(
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

    action execute_icmpgeneratorengine_stage0_act3(
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

    action drop_icmpgeneratorengine_stage0(bit<8> drop_code) {
        ig_to_eg_md.drop_flag = 1#1;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_DROP;
    }

    table icmpgeneratorengine_stage0_table {
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
            execute_icmpgeneratorengine_stage0_act0;
            execute_icmpgeneratorengine_stage0_act1;
            execute_icmpgeneratorengine_stage0_act2;
            execute_icmpgeneratorengine_stage0_act3;
            drop_icmpgeneratorengine_stage0;
            NoAction;
        }
        size = 2048;
        default_action = NoAction();
    }

    apply {
        icmpgeneratorengine_stage0_table.apply();
    }
}

control ChockIcmpGeneratorEngineStage1(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    ChockRegister<bit<32>>(2048, 0) stage_state_reg;
    ChockCounter(2048, CounterType_t.PACKETS_AND_BYTES) stage_counter;
    ChockMeter(2048) stage_meter;

    action execute_icmpgeneratorengine_stage1_act0(
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

    action execute_icmpgeneratorengine_stage1_act1(
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

    action execute_icmpgeneratorengine_stage1_act2(
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

    action execute_icmpgeneratorengine_stage1_act3(
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

    action drop_icmpgeneratorengine_stage1(bit<8> drop_code) {
        ig_to_eg_md.drop_flag = 1#1;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_DROP;
    }

    table icmpgeneratorengine_stage1_table {
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
            execute_icmpgeneratorengine_stage1_act0;
            execute_icmpgeneratorengine_stage1_act1;
            execute_icmpgeneratorengine_stage1_act2;
            execute_icmpgeneratorengine_stage1_act3;
            drop_icmpgeneratorengine_stage1;
            NoAction;
        }
        size = 2048;
        default_action = NoAction();
    }

    apply {
        icmpgeneratorengine_stage1_table.apply();
    }
}

control ChockIcmpGeneratorEngineStage2(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    ChockRegister<bit<32>>(2048, 0) stage_state_reg;
    ChockCounter(2048, CounterType_t.PACKETS_AND_BYTES) stage_counter;
    ChockMeter(2048) stage_meter;

    action execute_icmpgeneratorengine_stage2_act0(
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

    action execute_icmpgeneratorengine_stage2_act1(
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

    action execute_icmpgeneratorengine_stage2_act2(
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

    action execute_icmpgeneratorengine_stage2_act3(
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

    action drop_icmpgeneratorengine_stage2(bit<8> drop_code) {
        ig_to_eg_md.drop_flag = 1#1;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_DROP;
    }

    table icmpgeneratorengine_stage2_table {
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
            execute_icmpgeneratorengine_stage2_act0;
            execute_icmpgeneratorengine_stage2_act1;
            execute_icmpgeneratorengine_stage2_act2;
            execute_icmpgeneratorengine_stage2_act3;
            drop_icmpgeneratorengine_stage2;
            NoAction;
        }
        size = 2048;
        default_action = NoAction();
    }

    apply {
        icmpgeneratorengine_stage2_table.apply();
    }
}

control ChockIcmpGeneratorEngineStage3(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    ChockRegister<bit<32>>(2048, 0) stage_state_reg;
    ChockCounter(2048, CounterType_t.PACKETS_AND_BYTES) stage_counter;
    ChockMeter(2048) stage_meter;

    action execute_icmpgeneratorengine_stage3_act0(
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

    action execute_icmpgeneratorengine_stage3_act1(
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

    action execute_icmpgeneratorengine_stage3_act2(
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

    action execute_icmpgeneratorengine_stage3_act3(
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

    action drop_icmpgeneratorengine_stage3(bit<8> drop_code) {
        ig_to_eg_md.drop_flag = 1#1;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_DROP;
    }

    table icmpgeneratorengine_stage3_table {
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
            execute_icmpgeneratorengine_stage3_act0;
            execute_icmpgeneratorengine_stage3_act1;
            execute_icmpgeneratorengine_stage3_act2;
            execute_icmpgeneratorengine_stage3_act3;
            drop_icmpgeneratorengine_stage3;
            NoAction;
        }
        size = 2048;
        default_action = NoAction();
    }

    apply {
        icmpgeneratorengine_stage3_table.apply();
    }
}

control ChockIcmpGeneratorEngineStage4(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    ChockRegister<bit<32>>(2048, 0) stage_state_reg;
    ChockCounter(2048, CounterType_t.PACKETS_AND_BYTES) stage_counter;
    ChockMeter(2048) stage_meter;

    action execute_icmpgeneratorengine_stage4_act0(
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

    action execute_icmpgeneratorengine_stage4_act1(
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

    action execute_icmpgeneratorengine_stage4_act2(
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

    action execute_icmpgeneratorengine_stage4_act3(
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

    action drop_icmpgeneratorengine_stage4(bit<8> drop_code) {
        ig_to_eg_md.drop_flag = 1#1;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_DROP;
    }

    table icmpgeneratorengine_stage4_table {
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
            execute_icmpgeneratorengine_stage4_act0;
            execute_icmpgeneratorengine_stage4_act1;
            execute_icmpgeneratorengine_stage4_act2;
            execute_icmpgeneratorengine_stage4_act3;
            drop_icmpgeneratorengine_stage4;
            NoAction;
        }
        size = 2048;
        default_action = NoAction();
    }

    apply {
        icmpgeneratorengine_stage4_table.apply();
    }
}

control ChockIcmpGeneratorEngineStage5(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    ChockRegister<bit<32>>(2048, 0) stage_state_reg;
    ChockCounter(2048, CounterType_t.PACKETS_AND_BYTES) stage_counter;
    ChockMeter(2048) stage_meter;

    action execute_icmpgeneratorengine_stage5_act0(
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

    action execute_icmpgeneratorengine_stage5_act1(
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

    action execute_icmpgeneratorengine_stage5_act2(
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

    action execute_icmpgeneratorengine_stage5_act3(
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

    action drop_icmpgeneratorengine_stage5(bit<8> drop_code) {
        ig_to_eg_md.drop_flag = 1#1;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_DROP;
    }

    table icmpgeneratorengine_stage5_table {
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
            execute_icmpgeneratorengine_stage5_act0;
            execute_icmpgeneratorengine_stage5_act1;
            execute_icmpgeneratorengine_stage5_act2;
            execute_icmpgeneratorengine_stage5_act3;
            drop_icmpgeneratorengine_stage5;
            NoAction;
        }
        size = 2048;
        default_action = NoAction();
    }

    apply {
        icmpgeneratorengine_stage5_table.apply();
    }
}

control ChockIcmpGeneratorEngineStage6(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    ChockRegister<bit<32>>(2048, 0) stage_state_reg;
    ChockCounter(2048, CounterType_t.PACKETS_AND_BYTES) stage_counter;
    ChockMeter(2048) stage_meter;

    action execute_icmpgeneratorengine_stage6_act0(
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

    action execute_icmpgeneratorengine_stage6_act1(
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

    action execute_icmpgeneratorengine_stage6_act2(
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

    action execute_icmpgeneratorengine_stage6_act3(
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

    action drop_icmpgeneratorengine_stage6(bit<8> drop_code) {
        ig_to_eg_md.drop_flag = 1#1;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_DROP;
    }

    table icmpgeneratorengine_stage6_table {
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
            execute_icmpgeneratorengine_stage6_act0;
            execute_icmpgeneratorengine_stage6_act1;
            execute_icmpgeneratorengine_stage6_act2;
            execute_icmpgeneratorengine_stage6_act3;
            drop_icmpgeneratorengine_stage6;
            NoAction;
        }
        size = 2048;
        default_action = NoAction();
    }

    apply {
        icmpgeneratorengine_stage6_table.apply();
    }
}

control ChockIcmpGeneratorEngineStage7(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    ChockRegister<bit<32>>(2048, 0) stage_state_reg;
    ChockCounter(2048, CounterType_t.PACKETS_AND_BYTES) stage_counter;
    ChockMeter(2048) stage_meter;

    action execute_icmpgeneratorengine_stage7_act0(
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

    action execute_icmpgeneratorengine_stage7_act1(
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

    action execute_icmpgeneratorengine_stage7_act2(
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

    action execute_icmpgeneratorengine_stage7_act3(
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

    action drop_icmpgeneratorengine_stage7(bit<8> drop_code) {
        ig_to_eg_md.drop_flag = 1#1;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_DROP;
    }

    table icmpgeneratorengine_stage7_table {
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
            execute_icmpgeneratorengine_stage7_act0;
            execute_icmpgeneratorengine_stage7_act1;
            execute_icmpgeneratorengine_stage7_act2;
            execute_icmpgeneratorengine_stage7_act3;
            drop_icmpgeneratorengine_stage7;
            NoAction;
        }
        size = 2048;
        default_action = NoAction();
    }

    apply {
        icmpgeneratorengine_stage7_table.apply();
    }
}

#endif /* _CHOCK_PROTOCOLS_ICMP_GENERATOR_P4_ */
