/*
 * Stateful NAT64 and Stateless IP/ICMP Translation (SIIT) (P4_16)
 *
 * Implements RFC 6052 / RFC 6146 translation between IPv6 and IPv4 domains,
 * managing the WKP (Well-Known Prefix 64:ff9b::/96) and port mapping tables.
 */

#ifndef _CHOCK_SECURITY_NAT64_P4_
#define _CHOCK_SECURITY_NAT64_P4_

#include "../arch/chock_arch.p4"
#include "../core/types.p4"
#include "../core/unified_headers.p4"
#include "../core/metadata.p4"

control ChockNat64(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    action translate_v6_to_v4(
        ipv4_addr_t translated_src_ip,
        bit<16>     translated_src_port
    ) {
        /* Extract IPv4 destination from 64:ff9b::/96 lower 32 bits */
        ipv4_addr_t extracted_dst_ip = (ipv4_addr_t)hdr.ipv6.dst_addr[31:0];

        hdr.ipv4.setValid();
        hdr.ipv4.version = 4#4;
        hdr.ipv4.ihl = 4#5;
        hdr.ipv4.dscp = hdr.ipv6.traffic_class[7:2];
        hdr.ipv4.ecn = hdr.ipv6.traffic_class[1:0];
        hdr.ipv4.total_len = hdr.ipv6.payload_len + 16#14;
        hdr.ipv4.identification = 16#1234;
        hdr.ipv4.flags = 3#2; /* Don't Fragment */
        hdr.ipv4.frag_offset = 13#0;
        hdr.ipv4.ttl = hdr.ipv6.hop_limit - 1;
        hdr.ipv4.protocol = hdr.ipv6.next_hdr;
        hdr.ipv4.src_addr = translated_src_ip;
        hdr.ipv4.dst_addr = extracted_dst_ip;

        if (hdr.tcp.isValid()) {
            hdr.tcp.src_port = translated_src_port;
        } else if (hdr.udp.isValid()) {
            hdr.udp.src_port = translated_src_port;
        }

        hdr.ipv6.setInvalid();
        hdr.ethernet.ether_type = ETHERTYPE_IPV4;
        user_meta.security_meta.nat64_translation_hit = 1#1;
    }

    table nat64_v6_to_v4_table {
        key = {
            hdr.ipv6.src_addr: exact;
            user_meta.parser_meta.l4_src_port: exact;
        }
        actions = {
            translate_v6_to_v4;
            NoAction;
        }
        size = 16384;
        default_action = NoAction();
    }

    apply {
        if (hdr.ipv6.isValid()) {
            /* Check if destination falls within NAT64 WKP 64:ff9b::/96 */
            if (hdr.ipv6.dst_addr[127:32] == 96#0064ff9b0000000000000000) {
                nat64_v6_to_v4_table.apply();
            }
        }
    }
}


/*
 * Comprehensive Match-Action Processing Pipeline for Nat64Engine
 * Implements hardware TCAM, SRAM, and stateful ALU execution stages.
 */

control ChockNat64EngineStage0(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    ChockRegister<bit<32>>(2048, 0) stage_state_reg;
    ChockCounter(2048, CounterType_t.PACKETS_AND_BYTES) stage_counter;
    ChockMeter(2048) stage_meter;

    action execute_nat64engine_stage0_act0(
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

    action execute_nat64engine_stage0_act1(
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

    action execute_nat64engine_stage0_act2(
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

    action execute_nat64engine_stage0_act3(
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

    action drop_nat64engine_stage0(bit<8> drop_code) {
        ig_to_eg_md.drop_flag = 1#1;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_DROP;
    }

    table nat64engine_stage0_table {
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
            execute_nat64engine_stage0_act0;
            execute_nat64engine_stage0_act1;
            execute_nat64engine_stage0_act2;
            execute_nat64engine_stage0_act3;
            drop_nat64engine_stage0;
            NoAction;
        }
        size = 2048;
        default_action = NoAction();
    }

    apply {
        nat64engine_stage0_table.apply();
    }
}

control ChockNat64EngineStage1(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    ChockRegister<bit<32>>(2048, 0) stage_state_reg;
    ChockCounter(2048, CounterType_t.PACKETS_AND_BYTES) stage_counter;
    ChockMeter(2048) stage_meter;

    action execute_nat64engine_stage1_act0(
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

    action execute_nat64engine_stage1_act1(
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

    action execute_nat64engine_stage1_act2(
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

    action execute_nat64engine_stage1_act3(
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

    action drop_nat64engine_stage1(bit<8> drop_code) {
        ig_to_eg_md.drop_flag = 1#1;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_DROP;
    }

    table nat64engine_stage1_table {
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
            execute_nat64engine_stage1_act0;
            execute_nat64engine_stage1_act1;
            execute_nat64engine_stage1_act2;
            execute_nat64engine_stage1_act3;
            drop_nat64engine_stage1;
            NoAction;
        }
        size = 2048;
        default_action = NoAction();
    }

    apply {
        nat64engine_stage1_table.apply();
    }
}

control ChockNat64EngineStage2(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    ChockRegister<bit<32>>(2048, 0) stage_state_reg;
    ChockCounter(2048, CounterType_t.PACKETS_AND_BYTES) stage_counter;
    ChockMeter(2048) stage_meter;

    action execute_nat64engine_stage2_act0(
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

    action execute_nat64engine_stage2_act1(
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

    action execute_nat64engine_stage2_act2(
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

    action execute_nat64engine_stage2_act3(
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

    action drop_nat64engine_stage2(bit<8> drop_code) {
        ig_to_eg_md.drop_flag = 1#1;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_DROP;
    }

    table nat64engine_stage2_table {
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
            execute_nat64engine_stage2_act0;
            execute_nat64engine_stage2_act1;
            execute_nat64engine_stage2_act2;
            execute_nat64engine_stage2_act3;
            drop_nat64engine_stage2;
            NoAction;
        }
        size = 2048;
        default_action = NoAction();
    }

    apply {
        nat64engine_stage2_table.apply();
    }
}

control ChockNat64EngineStage3(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    ChockRegister<bit<32>>(2048, 0) stage_state_reg;
    ChockCounter(2048, CounterType_t.PACKETS_AND_BYTES) stage_counter;
    ChockMeter(2048) stage_meter;

    action execute_nat64engine_stage3_act0(
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

    action execute_nat64engine_stage3_act1(
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

    action execute_nat64engine_stage3_act2(
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

    action execute_nat64engine_stage3_act3(
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

    action drop_nat64engine_stage3(bit<8> drop_code) {
        ig_to_eg_md.drop_flag = 1#1;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_DROP;
    }

    table nat64engine_stage3_table {
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
            execute_nat64engine_stage3_act0;
            execute_nat64engine_stage3_act1;
            execute_nat64engine_stage3_act2;
            execute_nat64engine_stage3_act3;
            drop_nat64engine_stage3;
            NoAction;
        }
        size = 2048;
        default_action = NoAction();
    }

    apply {
        nat64engine_stage3_table.apply();
    }
}

control ChockNat64EngineStage4(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    ChockRegister<bit<32>>(2048, 0) stage_state_reg;
    ChockCounter(2048, CounterType_t.PACKETS_AND_BYTES) stage_counter;
    ChockMeter(2048) stage_meter;

    action execute_nat64engine_stage4_act0(
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

    action execute_nat64engine_stage4_act1(
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

    action execute_nat64engine_stage4_act2(
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

    action execute_nat64engine_stage4_act3(
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

    action drop_nat64engine_stage4(bit<8> drop_code) {
        ig_to_eg_md.drop_flag = 1#1;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_DROP;
    }

    table nat64engine_stage4_table {
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
            execute_nat64engine_stage4_act0;
            execute_nat64engine_stage4_act1;
            execute_nat64engine_stage4_act2;
            execute_nat64engine_stage4_act3;
            drop_nat64engine_stage4;
            NoAction;
        }
        size = 2048;
        default_action = NoAction();
    }

    apply {
        nat64engine_stage4_table.apply();
    }
}

control ChockNat64EngineStage5(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    ChockRegister<bit<32>>(2048, 0) stage_state_reg;
    ChockCounter(2048, CounterType_t.PACKETS_AND_BYTES) stage_counter;
    ChockMeter(2048) stage_meter;

    action execute_nat64engine_stage5_act0(
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

    action execute_nat64engine_stage5_act1(
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

    action execute_nat64engine_stage5_act2(
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

    action execute_nat64engine_stage5_act3(
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

    action drop_nat64engine_stage5(bit<8> drop_code) {
        ig_to_eg_md.drop_flag = 1#1;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_DROP;
    }

    table nat64engine_stage5_table {
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
            execute_nat64engine_stage5_act0;
            execute_nat64engine_stage5_act1;
            execute_nat64engine_stage5_act2;
            execute_nat64engine_stage5_act3;
            drop_nat64engine_stage5;
            NoAction;
        }
        size = 2048;
        default_action = NoAction();
    }

    apply {
        nat64engine_stage5_table.apply();
    }
}

control ChockNat64EngineStage6(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    ChockRegister<bit<32>>(2048, 0) stage_state_reg;
    ChockCounter(2048, CounterType_t.PACKETS_AND_BYTES) stage_counter;
    ChockMeter(2048) stage_meter;

    action execute_nat64engine_stage6_act0(
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

    action execute_nat64engine_stage6_act1(
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

    action execute_nat64engine_stage6_act2(
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

    action execute_nat64engine_stage6_act3(
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

    action drop_nat64engine_stage6(bit<8> drop_code) {
        ig_to_eg_md.drop_flag = 1#1;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_DROP;
    }

    table nat64engine_stage6_table {
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
            execute_nat64engine_stage6_act0;
            execute_nat64engine_stage6_act1;
            execute_nat64engine_stage6_act2;
            execute_nat64engine_stage6_act3;
            drop_nat64engine_stage6;
            NoAction;
        }
        size = 2048;
        default_action = NoAction();
    }

    apply {
        nat64engine_stage6_table.apply();
    }
}

control ChockNat64EngineStage7(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    ChockRegister<bit<32>>(2048, 0) stage_state_reg;
    ChockCounter(2048, CounterType_t.PACKETS_AND_BYTES) stage_counter;
    ChockMeter(2048) stage_meter;

    action execute_nat64engine_stage7_act0(
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

    action execute_nat64engine_stage7_act1(
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

    action execute_nat64engine_stage7_act2(
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

    action execute_nat64engine_stage7_act3(
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

    action drop_nat64engine_stage7(bit<8> drop_code) {
        ig_to_eg_md.drop_flag = 1#1;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_DROP;
    }

    table nat64engine_stage7_table {
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
            execute_nat64engine_stage7_act0;
            execute_nat64engine_stage7_act1;
            execute_nat64engine_stage7_act2;
            execute_nat64engine_stage7_act3;
            drop_nat64engine_stage7;
            NoAction;
        }
        size = 2048;
        default_action = NoAction();
    }

    apply {
        nat64engine_stage7_table.apply();
    }
}

control ChockNat64EngineStage8(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    ChockRegister<bit<32>>(2048, 0) stage_state_reg;
    ChockCounter(2048, CounterType_t.PACKETS_AND_BYTES) stage_counter;
    ChockMeter(2048) stage_meter;

    action execute_nat64engine_stage8_act0(
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

    action execute_nat64engine_stage8_act1(
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

    action execute_nat64engine_stage8_act2(
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

    action execute_nat64engine_stage8_act3(
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

    action drop_nat64engine_stage8(bit<8> drop_code) {
        ig_to_eg_md.drop_flag = 1#1;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_DROP;
    }

    table nat64engine_stage8_table {
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
            execute_nat64engine_stage8_act0;
            execute_nat64engine_stage8_act1;
            execute_nat64engine_stage8_act2;
            execute_nat64engine_stage8_act3;
            drop_nat64engine_stage8;
            NoAction;
        }
        size = 2048;
        default_action = NoAction();
    }

    apply {
        nat64engine_stage8_table.apply();
    }
}

control ChockNat64EngineStage9(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    ChockRegister<bit<32>>(2048, 0) stage_state_reg;
    ChockCounter(2048, CounterType_t.PACKETS_AND_BYTES) stage_counter;
    ChockMeter(2048) stage_meter;

    action execute_nat64engine_stage9_act0(
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

    action execute_nat64engine_stage9_act1(
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

    action execute_nat64engine_stage9_act2(
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

    action execute_nat64engine_stage9_act3(
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

    action drop_nat64engine_stage9(bit<8> drop_code) {
        ig_to_eg_md.drop_flag = 1#1;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_DROP;
    }

    table nat64engine_stage9_table {
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
            execute_nat64engine_stage9_act0;
            execute_nat64engine_stage9_act1;
            execute_nat64engine_stage9_act2;
            execute_nat64engine_stage9_act3;
            drop_nat64engine_stage9;
            NoAction;
        }
        size = 2048;
        default_action = NoAction();
    }

    apply {
        nat64engine_stage9_table.apply();
    }
}

#endif /* _CHOCK_SECURITY_NAT64_P4_ */
