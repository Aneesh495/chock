/*
 * Segment Routing over IPv6 (SRv6) End Behavior (P4_16)
 *
 * Implements standard SRv6 End function (RFC 8986 Section 4.1):
 * Decrements Segments Left pointer and updates the IPv6 destination address
 * with the active segment from the segment list.
 */

#ifndef _CHOCK_ROUTING_SRV6_END_P4_
#define _CHOCK_ROUTING_SRV6_END_P4_

#include "../arch/chock_arch.p4"
#include "../core/types.p4"
#include "../core/unified_headers.p4"
#include "../core/metadata.p4"

control ChockSrv6End(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    action advance_segment_pointer() {
        if (hdr.srv6_srh.segments_left > 0) {
            hdr.srv6_srh.segments_left = hdr.srv6_srh.segments_left - 1;
            user_meta.srv6_meta.segments_left = hdr.srv6_srh.segments_left;

            if (hdr.srv6_srh.segments_left == 0) {
                hdr.ipv6.dst_addr = hdr.srv6_seg0.sid;
            } else if (hdr.srv6_srh.segments_left == 1) {
                hdr.ipv6.dst_addr = hdr.srv6_seg1.sid;
            } else if (hdr.srv6_srh.segments_left == 2) {
                hdr.ipv6.dst_addr = hdr.srv6_seg2.sid;
            } else if (hdr.srv6_srh.segments_left == 3) {
                hdr.ipv6.dst_addr = hdr.srv6_seg3.sid;
            }
        } else {
            user_meta.parser_meta.parser_error_code = error.SrhSegmentExhausted;
        }
    }

    action drop_invalid_sid() {
        ig_to_eg_md.drop_flag = 1#1;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_DROP;
    }

    table srv6_local_sid_table {
        key = {
            hdr.ipv6.dst_addr: exact;
        }
        actions = {
            advance_segment_pointer;
            drop_invalid_sid;
        }
        size = 8192;
        default_action = drop_invalid_sid();
    }

    apply {
        if (hdr.srv6_srh.isValid()) {
            srv6_local_sid_table.apply();
        }
    }
}

#endif /* _CHOCK_ROUTING_SRV6_END_P4_ */
