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

#endif /* _CHOCK_SECURITY_NAT64_P4_ */
