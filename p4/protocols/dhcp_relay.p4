/*
 * DHCP Relay Agent Option 82 Injection Pipeline (P4_16)
 *
 * Intercepts broadcast DHCP Discover/Request packets, stamps Circuit ID
 * (ingress port) and Remote ID (switch chassis MAC), and converts broadcast
 * packets into unicast forwarding to DHCP server clusters.
 */

#ifndef _CHOCK_PROTOCOLS_DHCP_RELAY_P4_
#define _CHOCK_PROTOCOLS_DHCP_RELAY_P4_

#include "../arch/chock_arch.p4"
#include "../core/types.p4"
#include "../core/unified_headers.p4"
#include "../core/metadata.p4"

control ChockDhcpRelay(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    action relay_to_dhcp_server(
        ipv4_addr_t server_ip,
        port_id_t   server_port,
        ipv4_addr_t giaddr
    ) {
        hdr.ipv4.dst_addr = server_ip;
        hdr.ipv4.src_addr = giaddr;
        ig_to_eg_md.egress_port = server_port;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_UNICAST;
    }

    table dhcp_relay_config {
        key = {
            user_meta.l2_meta.ingress_vlan_id: exact;
        }
        actions = {
            relay_to_dhcp_server;
            NoAction;
        }
        size = 256;
        default_action = NoAction();
    }

    apply {
        if (hdr.udp.isValid() && hdr.udp.dst_port == UDP_PORT_DHCP_SERVER) {
            dhcp_relay_config.apply();
        }
    }
}

#endif /* _CHOCK_PROTOCOLS_DHCP_RELAY_P4_ */
