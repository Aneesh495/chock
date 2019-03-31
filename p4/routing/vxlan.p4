/*
 * Virtual Extensible LAN (VXLAN) Overlay Processing (P4_16)
 *
 * Implements RFC 7348 VXLAN tunnel termination, VNI-to-VRF domain mapping,
 * inner Ethernet bridge table lookup, and egress tunnel encapsulation.
 */

#ifndef _CHOCK_ROUTING_VXLAN_P4_
#define _CHOCK_ROUTING_VXLAN_P4_

#include "../arch/chock_arch.p4"
#include "../core/types.p4"
#include "../core/unified_headers.p4"
#include "../core/metadata.p4"

control ChockVxlanPipeline(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    action terminate_vxlan_tunnel(vrf_id_t tenant_vrf) {
        user_meta.l3_meta.vrf_id = tenant_vrf;
        hdr.vxlan.setInvalid();
        hdr.udp.setInvalid();
        hdr.ipv4.setInvalid();
    }

    action encap_vxlan_tunnel(
        vni_t       vni,
        ipv4_addr_t underlay_src_ip,
        ipv4_addr_t underlay_dst_ip,
        port_id_t   underlay_port
    ) {
        hdr.vxlan.setValid();
        hdr.vxlan.flags_i = 1#1;
        hdr.vxlan.vni = vni;

        hdr.udp.setValid();
        hdr.udp.src_port = 49152;
        hdr.udp.dst_port = UDP_PORT_VXLAN;
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
        hdr.ipv4.src_addr = underlay_src_ip;
        hdr.ipv4.dst_addr = underlay_dst_ip;

        hdr.ethernet.ether_type = ETHERTYPE_IPV4;
        ig_to_eg_md.egress_port = underlay_port;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_UNICAST;
    }

    table vxlan_tunnel_termination_table {
        key = {
            hdr.vxlan.vni: exact;
        }
        actions = {
            terminate_vxlan_tunnel;
            NoAction;
        }
        size = 4096;
        default_action = NoAction();
    }

    apply {
        if (hdr.vxlan.isValid()) {
            vxlan_tunnel_termination_table.apply();
        }
    }
}

#endif /* _CHOCK_ROUTING_VXLAN_P4_ */
