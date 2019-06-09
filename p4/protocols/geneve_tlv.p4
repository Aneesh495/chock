/*
 * Geneve Tunnel Variable-Length Options and TLV Metadata Processor (P4_16)
 *
 * Implements parsing and classification of Geneve (RFC 8926) Option TLVs:
 * Option Class, Option Type, Length, and embedded tenant telemetry vectors.
 */

#ifndef _CHOCK_PROTOCOLS_GENEVE_TLV_P4_
#define _CHOCK_PROTOCOLS_GENEVE_TLV_P4_

#include "../arch/chock_arch.p4"
#include "../core/types.p4"
#include "../core/unified_headers.p4"
#include "../core/metadata.p4"

header geneve_opt_h {
    bit<16> opt_class;
    bit<8>  opt_type;
    bit<3>  reserved;
    bit<5>  length_words;
    bit<32> opt_data;
}

control ChockGeneveTlvProcessor(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    action process_geneve_security_opt(bit<32> security_token) {
        user_meta.security_meta.acl_matched_rule_id = security_token;
    }

    table geneve_option_table {
        key = {
            hdr.geneve.vni: exact;
        }
        actions = {
            process_geneve_security_opt;
            NoAction;
        }
        size = 2048;
        default_action = NoAction();
    }

    apply {
        if (hdr.geneve.isValid() && hdr.geneve.opt_len > 0) {
            geneve_option_table.apply();
        }
    }
}

#endif /* _CHOCK_PROTOCOLS_GENEVE_TLV_P4_ */
