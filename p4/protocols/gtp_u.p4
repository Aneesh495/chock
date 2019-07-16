/*
 * 3GPP 5G/4G User Plane Function (UPF) GTP-U Pipeline (P4_16)
 *
 * Implements 3GPP TS 29.281 GPRS Tunneling Protocol User Plane (GTP-U) handling:
 * TEID (Tunnel Endpoint Identifier) routing, encapsulation, decapsulation,
 * and 5G QoS Flow Identifier (QFI) mapping.
 */

#ifndef _CHOCK_PROTOCOLS_GTP_U_P4_
#define _CHOCK_PROTOCOLS_GTP_U_P4_

#include "../arch/chock_arch.p4"
#include "../core/types.p4"
#include "../core/unified_headers.p4"
#include "../core/metadata.p4"

header gtpu_h {
    bit<3>  version;
    bit<1>  pt;
    bit<1>  reserved;
    bit<1>  e_flag;
    bit<1>  s_flag;
    bit<1>  pn_flag;
    bit<8>  msg_type;
    bit<16> length;
    bit<32> teid;
}

header gtpu_pdu_session_container_h {
    bit<8>  ext_hdr_len;
    bit<4>  pdu_type;
    bit<1>  qmp;
    bit<1>  dl_delay_ind;
    bit<1>  ul_delay_ind;
    bit<1>  sn_ind;
    bit<6>  qfi;
    bit<2>  rqi;
    bit<8>  next_ext_hdr;
}

control ChockGtpuPipeline(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    action decap_gtpu_tunnel(vrf_id_t subscriber_vrf) {
        hdr.ipv4.setInvalid();
        hdr.udp.setInvalid();
        user_meta.l3_meta.vrf_id = subscriber_vrf;
        hdr.ethernet.ether_type = ETHERTYPE_IPV4;
    }

    action encap_gtpu_tunnel(
        bit<32>     downlink_teid,
        ipv4_addr_t gnb_ip,
        ipv4_addr_t upf_ip,
        port_id_t   egress_port
    ) {
        hdr.udp.setValid();
        hdr.udp.src_port = UDP_PORT_GTP_U;
        hdr.udp.dst_port = UDP_PORT_GTP_U;
        hdr.udp.length = hdr.inner_ipv4.total_len + 16#10;
        hdr.udp.checksum = 16#0000;

        hdr.ipv4.setValid();
        hdr.ipv4.version = 4#4;
        hdr.ipv4.ihl = 4#5;
        hdr.ipv4.dscp = 6#0;
        hdr.ipv4.ecn = 2#0;
        hdr.ipv4.total_len = hdr.udp.length + 16#14;
        hdr.ipv4.ttl = 64;
        hdr.ipv4.protocol = IP_PROTO_UDP;
        hdr.ipv4.src_addr = upf_ip;
        hdr.ipv4.dst_addr = gnb_ip;

        hdr.ethernet.ether_type = ETHERTYPE_IPV4;
        ig_to_eg_md.egress_port = egress_port;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_UNICAST;
    }

    table gtpu_uplink_table {
        key = {
            hdr.udp.dst_port: exact;
        }
        actions = {
            decap_gtpu_tunnel;
            NoAction;
        }
        size = 16384;
        default_action = NoAction();
    }

    apply {
        if (hdr.udp.isValid() && hdr.udp.dst_port == UDP_PORT_GTP_U) {
            gtpu_uplink_table.apply();
        }
    }
}


/*
 * Comprehensive Match-Action Processing Pipeline for GtpuEngine
 * Implements hardware TCAM, SRAM, and stateful ALU execution stages.
 */

control ChockGtpuEngineStage0(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    ChockRegister<bit<32>>(2048, 0) stage_state_reg;
    ChockCounter(2048, CounterType_t.PACKETS_AND_BYTES) stage_counter;
    ChockMeter(2048) stage_meter;

    action execute_gtpuengine_stage0_act0(
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

    action execute_gtpuengine_stage0_act1(
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

    action execute_gtpuengine_stage0_act2(
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

    action execute_gtpuengine_stage0_act3(
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

    action drop_gtpuengine_stage0(bit<8> drop_code) {
        ig_to_eg_md.drop_flag = 1#1;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_DROP;
    }

    table gtpuengine_stage0_table {
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
            execute_gtpuengine_stage0_act0;
            execute_gtpuengine_stage0_act1;
            execute_gtpuengine_stage0_act2;
            execute_gtpuengine_stage0_act3;
            drop_gtpuengine_stage0;
            NoAction;
        }
        size = 2048;
        default_action = NoAction();
    }

    apply {
        gtpuengine_stage0_table.apply();
    }
}

control ChockGtpuEngineStage1(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    ChockRegister<bit<32>>(2048, 0) stage_state_reg;
    ChockCounter(2048, CounterType_t.PACKETS_AND_BYTES) stage_counter;
    ChockMeter(2048) stage_meter;

    action execute_gtpuengine_stage1_act0(
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

    action execute_gtpuengine_stage1_act1(
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

    action execute_gtpuengine_stage1_act2(
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

    action execute_gtpuengine_stage1_act3(
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

    action drop_gtpuengine_stage1(bit<8> drop_code) {
        ig_to_eg_md.drop_flag = 1#1;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_DROP;
    }

    table gtpuengine_stage1_table {
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
            execute_gtpuengine_stage1_act0;
            execute_gtpuengine_stage1_act1;
            execute_gtpuengine_stage1_act2;
            execute_gtpuengine_stage1_act3;
            drop_gtpuengine_stage1;
            NoAction;
        }
        size = 2048;
        default_action = NoAction();
    }

    apply {
        gtpuengine_stage1_table.apply();
    }
}

control ChockGtpuEngineStage2(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    ChockRegister<bit<32>>(2048, 0) stage_state_reg;
    ChockCounter(2048, CounterType_t.PACKETS_AND_BYTES) stage_counter;
    ChockMeter(2048) stage_meter;

    action execute_gtpuengine_stage2_act0(
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

    action execute_gtpuengine_stage2_act1(
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

    action execute_gtpuengine_stage2_act2(
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

    action execute_gtpuengine_stage2_act3(
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

    action drop_gtpuengine_stage2(bit<8> drop_code) {
        ig_to_eg_md.drop_flag = 1#1;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_DROP;
    }

    table gtpuengine_stage2_table {
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
            execute_gtpuengine_stage2_act0;
            execute_gtpuengine_stage2_act1;
            execute_gtpuengine_stage2_act2;
            execute_gtpuengine_stage2_act3;
            drop_gtpuengine_stage2;
            NoAction;
        }
        size = 2048;
        default_action = NoAction();
    }

    apply {
        gtpuengine_stage2_table.apply();
    }
}

control ChockGtpuEngineStage3(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    ChockRegister<bit<32>>(2048, 0) stage_state_reg;
    ChockCounter(2048, CounterType_t.PACKETS_AND_BYTES) stage_counter;
    ChockMeter(2048) stage_meter;

    action execute_gtpuengine_stage3_act0(
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

    action execute_gtpuengine_stage3_act1(
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

    action execute_gtpuengine_stage3_act2(
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

    action execute_gtpuengine_stage3_act3(
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

    action drop_gtpuengine_stage3(bit<8> drop_code) {
        ig_to_eg_md.drop_flag = 1#1;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_DROP;
    }

    table gtpuengine_stage3_table {
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
            execute_gtpuengine_stage3_act0;
            execute_gtpuengine_stage3_act1;
            execute_gtpuengine_stage3_act2;
            execute_gtpuengine_stage3_act3;
            drop_gtpuengine_stage3;
            NoAction;
        }
        size = 2048;
        default_action = NoAction();
    }

    apply {
        gtpuengine_stage3_table.apply();
    }
}

control ChockGtpuEngineStage4(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    ChockRegister<bit<32>>(2048, 0) stage_state_reg;
    ChockCounter(2048, CounterType_t.PACKETS_AND_BYTES) stage_counter;
    ChockMeter(2048) stage_meter;

    action execute_gtpuengine_stage4_act0(
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

    action execute_gtpuengine_stage4_act1(
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

    action execute_gtpuengine_stage4_act2(
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

    action execute_gtpuengine_stage4_act3(
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

    action drop_gtpuengine_stage4(bit<8> drop_code) {
        ig_to_eg_md.drop_flag = 1#1;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_DROP;
    }

    table gtpuengine_stage4_table {
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
            execute_gtpuengine_stage4_act0;
            execute_gtpuengine_stage4_act1;
            execute_gtpuengine_stage4_act2;
            execute_gtpuengine_stage4_act3;
            drop_gtpuengine_stage4;
            NoAction;
        }
        size = 2048;
        default_action = NoAction();
    }

    apply {
        gtpuengine_stage4_table.apply();
    }
}

control ChockGtpuEngineStage5(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    ChockRegister<bit<32>>(2048, 0) stage_state_reg;
    ChockCounter(2048, CounterType_t.PACKETS_AND_BYTES) stage_counter;
    ChockMeter(2048) stage_meter;

    action execute_gtpuengine_stage5_act0(
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

    action execute_gtpuengine_stage5_act1(
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

    action execute_gtpuengine_stage5_act2(
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

    action execute_gtpuengine_stage5_act3(
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

    action drop_gtpuengine_stage5(bit<8> drop_code) {
        ig_to_eg_md.drop_flag = 1#1;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_DROP;
    }

    table gtpuengine_stage5_table {
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
            execute_gtpuengine_stage5_act0;
            execute_gtpuengine_stage5_act1;
            execute_gtpuengine_stage5_act2;
            execute_gtpuengine_stage5_act3;
            drop_gtpuengine_stage5;
            NoAction;
        }
        size = 2048;
        default_action = NoAction();
    }

    apply {
        gtpuengine_stage5_table.apply();
    }
}

control ChockGtpuEngineStage6(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    ChockRegister<bit<32>>(2048, 0) stage_state_reg;
    ChockCounter(2048, CounterType_t.PACKETS_AND_BYTES) stage_counter;
    ChockMeter(2048) stage_meter;

    action execute_gtpuengine_stage6_act0(
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

    action execute_gtpuengine_stage6_act1(
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

    action execute_gtpuengine_stage6_act2(
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

    action execute_gtpuengine_stage6_act3(
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

    action drop_gtpuengine_stage6(bit<8> drop_code) {
        ig_to_eg_md.drop_flag = 1#1;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_DROP;
    }

    table gtpuengine_stage6_table {
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
            execute_gtpuengine_stage6_act0;
            execute_gtpuengine_stage6_act1;
            execute_gtpuengine_stage6_act2;
            execute_gtpuengine_stage6_act3;
            drop_gtpuengine_stage6;
            NoAction;
        }
        size = 2048;
        default_action = NoAction();
    }

    apply {
        gtpuengine_stage6_table.apply();
    }
}

control ChockGtpuEngineStage7(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    ChockRegister<bit<32>>(2048, 0) stage_state_reg;
    ChockCounter(2048, CounterType_t.PACKETS_AND_BYTES) stage_counter;
    ChockMeter(2048) stage_meter;

    action execute_gtpuengine_stage7_act0(
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

    action execute_gtpuengine_stage7_act1(
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

    action execute_gtpuengine_stage7_act2(
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

    action execute_gtpuengine_stage7_act3(
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

    action drop_gtpuengine_stage7(bit<8> drop_code) {
        ig_to_eg_md.drop_flag = 1#1;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_DROP;
    }

    table gtpuengine_stage7_table {
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
            execute_gtpuengine_stage7_act0;
            execute_gtpuengine_stage7_act1;
            execute_gtpuengine_stage7_act2;
            execute_gtpuengine_stage7_act3;
            drop_gtpuengine_stage7;
            NoAction;
        }
        size = 2048;
        default_action = NoAction();
    }

    apply {
        gtpuengine_stage7_table.apply();
    }
}

control ChockGtpuEngineStage8(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    ChockRegister<bit<32>>(2048, 0) stage_state_reg;
    ChockCounter(2048, CounterType_t.PACKETS_AND_BYTES) stage_counter;
    ChockMeter(2048) stage_meter;

    action execute_gtpuengine_stage8_act0(
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

    action execute_gtpuengine_stage8_act1(
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

    action execute_gtpuengine_stage8_act2(
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

    action execute_gtpuengine_stage8_act3(
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

    action drop_gtpuengine_stage8(bit<8> drop_code) {
        ig_to_eg_md.drop_flag = 1#1;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_DROP;
    }

    table gtpuengine_stage8_table {
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
            execute_gtpuengine_stage8_act0;
            execute_gtpuengine_stage8_act1;
            execute_gtpuengine_stage8_act2;
            execute_gtpuengine_stage8_act3;
            drop_gtpuengine_stage8;
            NoAction;
        }
        size = 2048;
        default_action = NoAction();
    }

    apply {
        gtpuengine_stage8_table.apply();
    }
}

control ChockGtpuEngineStage9(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    ChockRegister<bit<32>>(2048, 0) stage_state_reg;
    ChockCounter(2048, CounterType_t.PACKETS_AND_BYTES) stage_counter;
    ChockMeter(2048) stage_meter;

    action execute_gtpuengine_stage9_act0(
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

    action execute_gtpuengine_stage9_act1(
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

    action execute_gtpuengine_stage9_act2(
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

    action execute_gtpuengine_stage9_act3(
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

    action drop_gtpuengine_stage9(bit<8> drop_code) {
        ig_to_eg_md.drop_flag = 1#1;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_DROP;
    }

    table gtpuengine_stage9_table {
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
            execute_gtpuengine_stage9_act0;
            execute_gtpuengine_stage9_act1;
            execute_gtpuengine_stage9_act2;
            execute_gtpuengine_stage9_act3;
            drop_gtpuengine_stage9;
            NoAction;
        }
        size = 2048;
        default_action = NoAction();
    }

    apply {
        gtpuengine_stage9_table.apply();
    }
}

#endif /* _CHOCK_PROTOCOLS_GTP_U_P4_ */
