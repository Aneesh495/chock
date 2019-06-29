/*
 * IPSec Encapsulating Security Payload (ESP RFC 4303) Pipeline (P4_16)
 *
 * Inspects IPSec ESP headers (IP Protocol 50), performs Security Parameter
 * Index (SPI) classification, and routes packets to dedicated crypto offload engines.
 */

#ifndef _CHOCK_PROTOCOLS_IPSEC_ESP_P4_
#define _CHOCK_PROTOCOLS_IPSEC_ESP_P4_

#include "../arch/chock_arch.p4"
#include "../core/types.p4"
#include "../core/unified_headers.p4"
#include "../core/metadata.p4"

header ipsec_esp_h {
    bit<32> spi;
    bit<32> sequence_number;
}

control ChockIpsecEspPipeline(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    action route_to_crypto_offload(port_id_t crypto_port) {
        ig_to_eg_md.egress_port = crypto_port;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_UNICAST;
    }

    table esp_sa_table {
        key = {
            hdr.ipv4.dst_addr: exact;
        }
        actions = {
            route_to_crypto_offload;
            NoAction;
        }
        size = 4096;
        default_action = NoAction();
    }

    apply {
        if (hdr.ipv4.protocol == IP_PROTO_ESP) {
            esp_sa_table.apply();
        }
    }
}

#endif /* _CHOCK_PROTOCOLS_IPSEC_ESP_P4_ */
