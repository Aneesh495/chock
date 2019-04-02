/*
 * In-Band Network Telemetry (INT v2.1) Source Pipeline (P4_16)
 *
 * Encapsulates standard TCP/UDP packets with an INT shim header, sets up the
 * telemetry metadata header, and assigns the telemetry instruction bitmask.
 */

#ifndef _CHOCK_TELEMETRY_INT_SOURCE_P4_
#define _CHOCK_TELEMETRY_INT_SOURCE_P4_

#include "../arch/chock_arch.p4"
#include "../core/types.p4"
#include "../core/unified_headers.p4"
#include "../core/metadata.p4"
#include "int_headers.p4"

control ChockIntSource(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    action add_int_source_header(
        bit<16> ins_mask,
        bit<8>  hop_limit,
        bit<16> domain_id
    ) {
        hdr.int_shim.setValid();
        hdr.int_shim.int_type = 4#1; /* INT-MD */
        hdr.int_shim.npt = 2#0;
        hdr.int_shim.reserved = 2#0;
        hdr.int_shim.length_words = 8#03;
        hdr.int_shim.next_proto = hdr.tcp.isValid() ? (bit<16>)IP_PROTO_TCP : (bit<16>)IP_PROTO_UDP;

        hdr.int_metadata_hdr.setValid();
        hdr.int_metadata_hdr.version = 4#2;
        hdr.int_metadata_hdr.replication = 2#0;
        hdr.int_metadata_hdr.c_flag = 1#0;
        hdr.int_metadata_hdr.e_flag = 1#0;
        hdr.int_metadata_hdr.m_flag = 1#0;
        hdr.int_metadata_hdr.reserved = 7#0;
        hdr.int_metadata_hdr.hop_limit = hop_limit;
        hdr.int_metadata_hdr.remaining_hop_cnt = hop_limit;
        hdr.int_metadata_hdr.instruction_mask = ins_mask;
        hdr.int_metadata_hdr.domain_specific_id = domain_id;

        user_meta.int_meta.int_active = 1#1;
        user_meta.int_meta.int_source_node = 1#1;
        user_meta.int_meta.instruction_mask = ins_mask;
    }

    table int_source_policy_table {
        key = {
            hdr.ipv4.src_addr: ternary;
            hdr.ipv4.dst_addr: ternary;
            hdr.tcp.dst_port:  ternary;
        }
        actions = {
            add_int_source_header;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    apply {
        if (hdr.ipv4.isValid() && !hdr.int_shim.isValid()) {
            int_source_policy_table.apply();
        }
    }
}

#endif /* _CHOCK_TELEMETRY_INT_SOURCE_P4_ */
