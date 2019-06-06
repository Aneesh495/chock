/*
 * Autonomous In-Network ARP Proxy and Responder (P4_16)
 *
 * Synthesizes ARP Reply messages directly in data plane for configured gateway IPs,
 * eliminating control plane CPU interrupts and broadcast storm propagation.
 */

#ifndef _CHOCK_PROTOCOLS_ARP_RESPONDER_P4_
#define _CHOCK_PROTOCOLS_ARP_RESPONDER_P4_

#include "../arch/chock_arch.p4"
#include "../core/types.p4"
#include "../core/unified_headers.p4"
#include "../core/metadata.p4"

control ChockArpResponder(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    action reply_with_gateway_mac(mac_addr_t gateway_mac) {
        hdr.arp.opcode = ARP_OP_REPLY;
        hdr.arp.target_hw_addr = hdr.arp.sender_hw_addr;
        hdr.arp.target_proto_addr = hdr.arp.sender_proto_addr;
        hdr.arp.sender_hw_addr = gateway_mac;
        hdr.arp.sender_proto_addr = hdr.arp.target_proto_addr;

        hdr.ethernet.dst_addr = hdr.ethernet.src_addr;
        hdr.ethernet.src_addr = gateway_mac;

        ig_to_eg_md.egress_port = ig_intr_md.ingress_port;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_UNICAST;
    }

    table gateway_arp_table {
        key = {
            hdr.arp.target_proto_addr: exact;
        }
        actions = {
            reply_with_gateway_mac;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    apply {
        if (hdr.arp.isValid() && hdr.arp.opcode == ARP_OP_REQUEST) {
            gateway_arp_table.apply();
        }
    }
}

#endif /* _CHOCK_PROTOCOLS_ARP_RESPONDER_P4_ */
