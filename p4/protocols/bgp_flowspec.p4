/*
 * BGP FlowSpec (RFC 8955 / RFC 5575) Dissemination of Flow Specification Rules (P4_16)
 *
 * Implements line-rate data plane enforcement of BGP FlowSpec rules:
 * Destination/Source prefix matching, IP protocol, port ranges, packet length filters,
 * DSCP matching, and mitigation actions (rate-limiting, traffic marking, redirection, drop).
 */

#ifndef _CHOCK_PROTOCOLS_BGP_FLOWSPEC_P4_
#define _CHOCK_PROTOCOLS_BGP_FLOWSPEC_P4_

#include "../arch/chock_arch.p4"
#include "../core/types.p4"
#include "../core/unified_headers.p4"
#include "../core/metadata.p4"

control ChockBgpFlowSpec(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    ChockCounter(8192, CounterType_t.PACKETS_AND_BYTES) flowspec_rule_counters;
    ChockMeter(8192) flowspec_rate_meters;

    action flowspec_traffic_rate_limit(bit<32> meter_idx) {
        MeterColor_t color = flowspec_rate_meters.execute(meter_idx, (bit<32>)ig_intr_md.packet_length_bytes);
        if (color == MeterColor_t.COLOR_RED) {
            ig_to_eg_md.drop_flag = 1#1;
            ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_DROP;
        }
        flowspec_rule_counters.count(meter_idx);
    }

    action flowspec_traffic_action_drop(bit<32> rule_id) {
        ig_to_eg_md.drop_flag = 1#1;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_DROP;
        flowspec_rule_counters.count(rule_id);
    }

    action flowspec_traffic_mark_dscp(bit<6> new_dscp, bit<32> rule_id) {
        if (hdr.ipv4.isValid()) {
            hdr.ipv4.dscp = new_dscp;
        } else if (hdr.ipv6.isValid()) {
            hdr.ipv6.traffic_class[7:2] = new_dscp;
        }
        flowspec_rule_counters.count(rule_id);
    }

    action flowspec_redirect_vrf(vrf_id_t target_vrf, bit<32> rule_id) {
        user_meta.l3_meta.vrf_id = target_vrf;
        flowspec_rule_counters.count(rule_id);
    }

    table flowspec_ipv4_table {
        key = {
            hdr.ipv4.dst_addr:                 ternary;
            hdr.ipv4.src_addr:                 ternary;
            hdr.ipv4.protocol:                 ternary;
            user_meta.parser_meta.l4_src_port: ternary;
            user_meta.parser_meta.l4_dst_port: ternary;
            hdr.ipv4.dscp:                     ternary;
            hdr.tcp.flags:                     ternary;
        }
        actions = {
            flowspec_traffic_rate_limit;
            flowspec_traffic_action_drop;
            flowspec_traffic_mark_dscp;
            flowspec_redirect_vrf;
            NoAction;
        }
        size = 8192;
        default_action = NoAction();
    }

    apply {
        if (hdr.ipv4.isValid()) {
            flowspec_ipv4_table.apply();
        }
    }
}

#endif /* _CHOCK_PROTOCOLS_BGP_FLOWSPEC_P4_ */
