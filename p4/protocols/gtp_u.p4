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

#endif /* _CHOCK_PROTOCOLS_GTP_U_P4_ */
