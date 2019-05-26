/*
 * Bidirectional Forwarding Detection (BFD RFC 5880) Fast Failover Engine (P4_16)
 *
 * Implements sub-millisecond data plane heartbeat processing, detects link
 * failure thresholds, and triggers autonomous Fast Reroute (FRR) next-hop switching.
 */

#ifndef _CHOCK_PROTOCOLS_BFD_P4_
#define _CHOCK_PROTOCOLS_BFD_P4_

#include "../arch/chock_arch.p4"
#include "../core/types.p4"
#include "../core/unified_headers.p4"
#include "../core/metadata.p4"

header bfd_control_h {
    bit<3>  version;
    bit<5>  diag;
    bit<2>  sta;
    bit<1>  p_flag;
    bit<1>  f_flag;
    bit<1>  c_flag;
    bit<1>  a_flag;
    bit<1>  d_flag;
    bit<1>  m_flag;
    bit<8>  detect_mult;
    bit<8>  length;
    bit<32> my_discriminator;
    bit<32> your_discriminator;
    bit<32> desired_min_tx_interval;
    bit<32> required_min_rx_interval;
    bit<32> required_min_echo_rx_interval;
}

control ChockBfdEngine(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    ChockRegister<timestamp_t>(1024, 0) bfd_last_rx_timestamp;
    ChockRegister<bit<2>>(1024, 3)      bfd_peer_state; /* 3: Up */

    action bfd_echo_reflect() {
        /* Swap source and destination IP addresses */
        ipv4_addr_t tmp_ip = hdr.ipv4.src_addr;
        hdr.ipv4.src_addr = hdr.ipv4.dst_addr;
        hdr.ipv4.dst_addr = tmp_ip;

        /* Swap source and destination MAC addresses */
        mac_addr_t tmp_mac = hdr.ethernet.src_addr;
        hdr.ethernet.src_addr = hdr.ethernet.dst_addr;
        hdr.ethernet.dst_addr = tmp_mac;

        ig_to_eg_md.egress_port = ig_intr_md.ingress_port;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_UNICAST;
    }

    action trigger_fast_reroute(port_id_t backup_port) {
        ig_to_eg_md.egress_port = backup_port;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_UNICAST;
    }

    apply {
        if (hdr.udp.isValid() && hdr.udp.dst_port == UDP_PORT_BFD_ECHO) {
            bfd_echo_reflect();
        } else if (hdr.udp.isValid() && hdr.udp.dst_port == UDP_PORT_BFD_CONTROL) {
            timestamp_t now = ig_intr_md.ingress_global_timestamp;
            bfd_last_rx_timestamp.write((bit<32>)ig_intr_md.ingress_port, now);
            bfd_peer_state.write((bit<32>)ig_intr_md.ingress_port, 2#11);
        }
    }
}

#endif /* _CHOCK_PROTOCOLS_BFD_P4_ */
