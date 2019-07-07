/*
 * 802.1Q and QinQ VLAN Classification and Tag Manipulation (P4_16)
 *
 * Implements ingress VLAN domain classification, access and trunk port validation,
 * native VLAN tagging, and egress tag push/pop/translation actions.
 */

#ifndef _CHOCK_ROUTING_VLAN_P4_
#define _CHOCK_ROUTING_VLAN_P4_

#include "../arch/chock_arch.p4"
#include "../core/types.p4"
#include "../core/unified_headers.p4"
#include "../core/metadata.p4"

control ChockVlanPipeline(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    action set_access_port_vlan(vlan_id_t default_vid) {
        user_meta.l2_meta.ingress_vlan_id = default_vid;
        hdr.vlan.setValid();
        hdr.vlan.pcp = 3#0;
        hdr.vlan.dei = 1#0;
        hdr.vlan.vid = default_vid;
        hdr.vlan.ether_type = hdr.ethernet.ether_type;
        hdr.ethernet.ether_type = ETHERTYPE_VLAN;
    }

    action validate_trunk_vlan(vlan_id_t allowed_vid) {
        user_meta.l2_meta.ingress_vlan_id = allowed_vid;
    }

    action translate_vlan_tag(vlan_id_t new_vid) {
        hdr.vlan.vid = new_vid;
        user_meta.l2_meta.egress_vlan_id = new_vid;
    }

    action push_provider_tag(vlan_id_t s_vid, bit<3> pcp) {
        hdr.provider_vlan.setValid();
        hdr.provider_vlan.pcp = pcp;
        hdr.provider_vlan.dei = 1#0;
        hdr.provider_vlan.vid = s_vid;
        hdr.provider_vlan.ether_type = hdr.ethernet.ether_type;
        hdr.ethernet.ether_type = ETHERTYPE_PROVIDER_VLAN;
    }

    action pop_vlan_tag() {
        if (hdr.vlan.isValid()) {
            hdr.ethernet.ether_type = hdr.vlan.ether_type;
            hdr.vlan.setInvalid();
        }
    }

    action drop_vlan_mismatch() {
        ig_to_eg_md.drop_flag = 1#1;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_DROP;
    }

    table ingress_port_vlan_table {
        key = {
            ig_intr_md.ingress_port:           exact;
            user_meta.l2_meta.ingress_vlan_id: ternary;
        }
        actions = {
            set_access_port_vlan;
            validate_trunk_vlan;
            push_provider_tag;
            drop_vlan_mismatch;
        }
        size = 4096;
        default_action = drop_vlan_mismatch();
    }

    table egress_vlan_translation_table {
        key = {
            ig_to_eg_md.egress_port:          exact;
            user_meta.l2_meta.ingress_vlan_id: exact;
        }
        actions = {
            translate_vlan_tag;
            pop_vlan_tag;
            NoAction;
        }
        size = 4096;
        default_action = NoAction();
    }

    apply {
        ingress_port_vlan_table.apply();
        egress_vlan_translation_table.apply();
    }
}


/*
 * Comprehensive Match-Action Processing Pipeline for VlanEngine
 * Implements hardware TCAM, SRAM, and stateful ALU execution stages.
 */

control ChockVlanEngineStage0(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    ChockRegister<bit<32>>(2048, 0) stage_state_reg;
    ChockCounter(2048, CounterType_t.PACKETS_AND_BYTES) stage_counter;
    ChockMeter(2048) stage_meter;

    action execute_vlanengine_stage0_act0(
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

    action execute_vlanengine_stage0_act1(
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

    action execute_vlanengine_stage0_act2(
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

    action execute_vlanengine_stage0_act3(
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

    action drop_vlanengine_stage0(bit<8> drop_code) {
        ig_to_eg_md.drop_flag = 1#1;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_DROP;
    }

    table vlanengine_stage0_table {
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
            execute_vlanengine_stage0_act0;
            execute_vlanengine_stage0_act1;
            execute_vlanengine_stage0_act2;
            execute_vlanengine_stage0_act3;
            drop_vlanengine_stage0;
            NoAction;
        }
        size = 2048;
        default_action = NoAction();
    }

    apply {
        vlanengine_stage0_table.apply();
    }
}

control ChockVlanEngineStage1(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    ChockRegister<bit<32>>(2048, 0) stage_state_reg;
    ChockCounter(2048, CounterType_t.PACKETS_AND_BYTES) stage_counter;
    ChockMeter(2048) stage_meter;

    action execute_vlanengine_stage1_act0(
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

    action execute_vlanengine_stage1_act1(
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

    action execute_vlanengine_stage1_act2(
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

    action execute_vlanengine_stage1_act3(
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

    action drop_vlanengine_stage1(bit<8> drop_code) {
        ig_to_eg_md.drop_flag = 1#1;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_DROP;
    }

    table vlanengine_stage1_table {
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
            execute_vlanengine_stage1_act0;
            execute_vlanengine_stage1_act1;
            execute_vlanengine_stage1_act2;
            execute_vlanengine_stage1_act3;
            drop_vlanengine_stage1;
            NoAction;
        }
        size = 2048;
        default_action = NoAction();
    }

    apply {
        vlanengine_stage1_table.apply();
    }
}

control ChockVlanEngineStage2(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    ChockRegister<bit<32>>(2048, 0) stage_state_reg;
    ChockCounter(2048, CounterType_t.PACKETS_AND_BYTES) stage_counter;
    ChockMeter(2048) stage_meter;

    action execute_vlanengine_stage2_act0(
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

    action execute_vlanengine_stage2_act1(
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

    action execute_vlanengine_stage2_act2(
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

    action execute_vlanengine_stage2_act3(
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

    action drop_vlanengine_stage2(bit<8> drop_code) {
        ig_to_eg_md.drop_flag = 1#1;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_DROP;
    }

    table vlanengine_stage2_table {
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
            execute_vlanengine_stage2_act0;
            execute_vlanengine_stage2_act1;
            execute_vlanengine_stage2_act2;
            execute_vlanengine_stage2_act3;
            drop_vlanengine_stage2;
            NoAction;
        }
        size = 2048;
        default_action = NoAction();
    }

    apply {
        vlanengine_stage2_table.apply();
    }
}

control ChockVlanEngineStage3(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    ChockRegister<bit<32>>(2048, 0) stage_state_reg;
    ChockCounter(2048, CounterType_t.PACKETS_AND_BYTES) stage_counter;
    ChockMeter(2048) stage_meter;

    action execute_vlanengine_stage3_act0(
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

    action execute_vlanengine_stage3_act1(
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

    action execute_vlanengine_stage3_act2(
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

    action execute_vlanengine_stage3_act3(
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

    action drop_vlanengine_stage3(bit<8> drop_code) {
        ig_to_eg_md.drop_flag = 1#1;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_DROP;
    }

    table vlanengine_stage3_table {
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
            execute_vlanengine_stage3_act0;
            execute_vlanengine_stage3_act1;
            execute_vlanengine_stage3_act2;
            execute_vlanengine_stage3_act3;
            drop_vlanengine_stage3;
            NoAction;
        }
        size = 2048;
        default_action = NoAction();
    }

    apply {
        vlanengine_stage3_table.apply();
    }
}

control ChockVlanEngineStage4(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    ChockRegister<bit<32>>(2048, 0) stage_state_reg;
    ChockCounter(2048, CounterType_t.PACKETS_AND_BYTES) stage_counter;
    ChockMeter(2048) stage_meter;

    action execute_vlanengine_stage4_act0(
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

    action execute_vlanengine_stage4_act1(
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

    action execute_vlanengine_stage4_act2(
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

    action execute_vlanengine_stage4_act3(
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

    action drop_vlanengine_stage4(bit<8> drop_code) {
        ig_to_eg_md.drop_flag = 1#1;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_DROP;
    }

    table vlanengine_stage4_table {
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
            execute_vlanengine_stage4_act0;
            execute_vlanengine_stage4_act1;
            execute_vlanengine_stage4_act2;
            execute_vlanengine_stage4_act3;
            drop_vlanengine_stage4;
            NoAction;
        }
        size = 2048;
        default_action = NoAction();
    }

    apply {
        vlanengine_stage4_table.apply();
    }
}

control ChockVlanEngineStage5(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    ChockRegister<bit<32>>(2048, 0) stage_state_reg;
    ChockCounter(2048, CounterType_t.PACKETS_AND_BYTES) stage_counter;
    ChockMeter(2048) stage_meter;

    action execute_vlanengine_stage5_act0(
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

    action execute_vlanengine_stage5_act1(
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

    action execute_vlanengine_stage5_act2(
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

    action execute_vlanengine_stage5_act3(
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

    action drop_vlanengine_stage5(bit<8> drop_code) {
        ig_to_eg_md.drop_flag = 1#1;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_DROP;
    }

    table vlanengine_stage5_table {
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
            execute_vlanengine_stage5_act0;
            execute_vlanengine_stage5_act1;
            execute_vlanengine_stage5_act2;
            execute_vlanengine_stage5_act3;
            drop_vlanengine_stage5;
            NoAction;
        }
        size = 2048;
        default_action = NoAction();
    }

    apply {
        vlanengine_stage5_table.apply();
    }
}

control ChockVlanEngineStage6(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    ChockRegister<bit<32>>(2048, 0) stage_state_reg;
    ChockCounter(2048, CounterType_t.PACKETS_AND_BYTES) stage_counter;
    ChockMeter(2048) stage_meter;

    action execute_vlanengine_stage6_act0(
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

    action execute_vlanengine_stage6_act1(
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

    action execute_vlanengine_stage6_act2(
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

    action execute_vlanengine_stage6_act3(
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

    action drop_vlanengine_stage6(bit<8> drop_code) {
        ig_to_eg_md.drop_flag = 1#1;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_DROP;
    }

    table vlanengine_stage6_table {
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
            execute_vlanengine_stage6_act0;
            execute_vlanengine_stage6_act1;
            execute_vlanengine_stage6_act2;
            execute_vlanengine_stage6_act3;
            drop_vlanengine_stage6;
            NoAction;
        }
        size = 2048;
        default_action = NoAction();
    }

    apply {
        vlanengine_stage6_table.apply();
    }
}

control ChockVlanEngineStage7(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    ChockRegister<bit<32>>(2048, 0) stage_state_reg;
    ChockCounter(2048, CounterType_t.PACKETS_AND_BYTES) stage_counter;
    ChockMeter(2048) stage_meter;

    action execute_vlanengine_stage7_act0(
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

    action execute_vlanengine_stage7_act1(
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

    action execute_vlanengine_stage7_act2(
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

    action execute_vlanengine_stage7_act3(
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

    action drop_vlanengine_stage7(bit<8> drop_code) {
        ig_to_eg_md.drop_flag = 1#1;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_DROP;
    }

    table vlanengine_stage7_table {
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
            execute_vlanengine_stage7_act0;
            execute_vlanengine_stage7_act1;
            execute_vlanengine_stage7_act2;
            execute_vlanengine_stage7_act3;
            drop_vlanengine_stage7;
            NoAction;
        }
        size = 2048;
        default_action = NoAction();
    }

    apply {
        vlanengine_stage7_table.apply();
    }
}

#endif /* _CHOCK_ROUTING_VLAN_P4_ */
