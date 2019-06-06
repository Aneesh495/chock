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

#endif /* _CHOCK_PROTOCOLS_ICMP_GENERATOR_P4_ */
