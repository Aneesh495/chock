/*
 * Financial Market Data A/B Feed Arbitrator and Deduplicator (P4_16)
 *
 * Implements hardware line arbitration across dual redundant market data feeds
 * (Line A and Line B). Statically eliminates duplicate messages using sequence
 * number registers and immediately forwards the earliest arriving packet.
 */

#ifndef _CHOCK_ACCEL_MARKET_FEED_P4_
#define _CHOCK_ACCEL_MARKET_FEED_P4_

#include "../arch/chock_arch.p4"
#include "../core/types.p4"
#include "../core/unified_headers.p4"
#include "../core/metadata.p4"
#include "market_feed_headers.p4"

control ChockMarketFeedArbitrator(
    inout headers_t hdr,
    inout user_metadata_t user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md
) {
    /* Tracks last forwarded sequence number per market channel (256 channels) */
    ChockRegister<bit<32>>(256, 0) last_forwarded_seq_reg;
    ChockCounter(256, CounterType_t.PACKETS) duplicate_drop_counters;

    action forward_market_packet(port_id_t trading_server_port) {
        ig_to_eg_md.egress_port = trading_server_port;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_UNICAST;
        user_meta.accel_meta.market_feed_is_duplicate = 1#0;
    }

    action drop_duplicate_packet(bit<32> channel_idx) {
        ig_to_eg_md.drop_flag = 1#1;
        ig_to_eg_md.decision = ForwardingDecision_t.FORWARD_DROP;
        user_meta.accel_meta.market_feed_is_duplicate = 1#1;
        duplicate_drop_counters.count(channel_idx);
    }

    table channel_forwarding_table {
        key = {
            hdr.market_feed.channel_id: exact;
        }
        actions = {
            forward_market_packet;
        }
        size = 256;
        default_action = forward_market_packet(1);
    }

    apply {
        if (hdr.market_feed.isValid()) {
            bit<32> chan_idx = (bit<32>)hdr.market_feed.channel_id;
            bit<32> last_seq = last_forwarded_seq_reg.read(chan_idx);
            bit<32> incoming_seq = hdr.market_feed.sequence_number;

            if (incoming_seq > last_seq) {
                /* First arrival from either Line A or Line B */
                last_forwarded_seq_reg.write(chan_idx, incoming_seq);
                channel_forwarding_table.apply();
            } else {
                /* Duplicate arrival */
                drop_duplicate_packet(chan_idx);
            }
        }
    }
}

#endif /* _CHOCK_ACCEL_MARKET_FEED_P4_ */
