/*
 * Financial Market Data Arbitrator and Normalizer Header (P4_16)
 *
 * Defines real-time market data feed arbitration and sequence deduplication headers.
 */

#ifndef _CHOCK_ACCEL_MARKET_FEED_HEADERS_P4_
#define _CHOCK_ACCEL_MARKET_FEED_HEADERS_P4_

#include "../core/types.p4"

header market_feed_h {
    bit<8>      channel_id;
    bit<8>      line_id;
    bit<16>     message_count;
    bit<32>     sequence_number;
    timestamp_t feed_timestamp_ns;
}

#endif /* _CHOCK_ACCEL_MARKET_FEED_HEADERS_P4_ */
