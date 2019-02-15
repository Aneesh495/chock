/*
 * Chock Programmable Switch Architecture (P4_16)
 *
 * Defines the ChockSwitch programmable packet processing pipeline,
 * standard interfaces, externs, intrinsic metadata, and processing stages.
 */

#ifndef _CHOCK_ARCH_P4_
#define _CHOCK_ARCH_P4_

/*
 * Standard integer types and aliases
 */
typedef bit<9>   port_id_t;
typedef bit<16>  vlan_id_t;
typedef bit<48>  mac_addr_t;
typedef bit<32>  ipv4_addr_t;
typedef bit<128> ipv6_addr_t;
typedef bit<16>  vrf_id_t;
typedef bit<32>  flow_id_t;
typedef bit<48>  timestamp_t;
typedef bit<32>  latency_t;
typedef bit<24>  vni_t;
typedef bit<20>  mpls_label_t;
typedef bit<19>  qdepth_t;

/*
 * Packet forwarding decision enumeration
 */
enum ForwardingDecision_t {
    FORWARD_UNICAST,
    FORWARD_MULTICAST,
    FORWARD_BROADCAST,
    FORWARD_TO_CPU,
    FORWARD_DROP,
    FORWARD_RESUBMIT,
    FORWARD_RECIRCULATE
}

/*
 * Standard packet parser error enumeration
 */
error {
    NoError,
    PacketTooShort,
    NoMatch,
    StackOutOfBounds,
    HeaderTooShort,
    ParserTimeout,
    InvalidChecksum,
    InvalidIpv4HeaderLength,
    InvalidIpv4TotalLength,
    InvalidIpv6PayloadLength,
    UnknownEtherType,
    UnknownIpProtocol,
    SrhSegmentExhausted,
    IntShimInvalid,
    IntHopLimitExceeded,
    NetCacheMalformedQuery,
    NetPaxosInvalidPhase
}

/*
 * Ingress Intrinsic Metadata provided by the Chock switch port hardware
 */
struct chock_ingress_intrinsic_metadata_t {
    port_id_t    ingress_port;
    port_id_t    ingress_physical_port;
    timestamp_t  ingress_global_timestamp;
    timestamp_t  ingress_mac_timestamp;
    bit<16>      packet_length_bytes;
    bit<3>       ingress_priority;
    bit<1>       resubmit_flag;
    bit<1>       recirculate_flag;
    bit<8>       ingress_error;
}

/*
 * Ingress-to-Egress Metadata passed to Traffic Manager
 */
struct chock_ingress_to_egress_metadata_t {
    port_id_t    egress_port;
    bit<16>      multicast_group;
    ForwardingDecision_t decision;
    bit<3>       traffic_class;
    bit<8>       queue_id;
    bit<1>       drop_flag;
    bit<1>       bypass_egress;
}

/*
 * Egress Intrinsic Metadata provided by Traffic Manager to Egress Pipeline
 */
struct chock_egress_intrinsic_metadata_t {
    port_id_t    egress_port;
    port_id_t    egress_physical_port;
    timestamp_t  egress_global_timestamp;
    timestamp_t  enq_timestamp;
    latency_t    queue_latency_ns;
    qdepth_t     queue_depth_packets;
    qdepth_t     queue_depth_bytes;
    bit<8>       queue_id;
    bit<3>       traffic_class;
    bit<1>       deflection_flag;
}

/*
 * Standard packet_in interface for streaming bytes from network
 */
extern packet_in {
    void extract<T>(out T header_to_extract);
    void extract<T>(out T variable_header, in bit<32> variable_field_size_in_bits);
    T lookahead<T>();
    void advance(in bit<32> size_in_bits);
    bit<32> length();
}

/*
 * Standard packet_out interface for serializing headers to network
 */
extern packet_out {
    void emit<T>(in T header_to_emit);
}

/*
 * Chock Register Extern for stateful memory arrays
 */
extern ChockRegister<T> {
    ChockRegister(bit<32> size, T initial_value);
    T read(in bit<32> index);
    void write(in bit<32> index, in T value);
    T compare_and_swap(in bit<32> index, in T compare_val, in T new_val);
}

/*
 * Chock Counter Extern for packet and byte metrics
 */
enum CounterType_t {
    PACKETS,
    BYTES,
    PACKETS_AND_BYTES
}

extern ChockCounter {
    ChockCounter(bit<32> size, CounterType_t counter_type);
    void count(in bit<32> index);
    void count_bytes(in bit<32> index, in bit<32> byte_count);
}

/*
 * Chock Meter Extern for RFC 2698 Two-Rate Three-Color Marking
 */
enum MeterColor_t {
    COLOR_GREEN,
    COLOR_YELLOW,
    COLOR_RED
}

extern ChockMeter {
    ChockMeter(bit<32> size);
    MeterColor_t execute(in bit<32> index, in bit<32> packet_bytes);
}

/*
 * Chock Hash Extern supporting CRC32, Murmur3, and polynomial hashing
 */
enum HashAlgorithm_t {
    HASH_CRC32,
    HASH_CRC16,
    HASH_MURMUR3,
    HASH_IDENTITY,
    HASH_POLYNOMIAL_STAGE0,
    HASH_POLYNOMIAL_STAGE1,
    HASH_POLYNOMIAL_STAGE2,
    HASH_POLYNOMIAL_STAGE3
}

extern ChockHash<O> {
    ChockHash(HashAlgorithm_t algorithm);
    O compute<D>(in D data);
    O compute_with_salt<D>(in D data, in bit<32> salt);
}

/*
 * Chock Random Number Generator Extern
 */
extern ChockRandom<T> {
    ChockRandom();
    T get(in T min_val, in T max_val);
}

/*
 * Chock Digest Extern for learning and control plane dispatch
 */
extern ChockDigest<T> {
    ChockDigest();
    void pack_and_send(in T message);
}

/*
 * Programmable Pipeline Block Interfaces
 */
parser ChockParser<H, M>(
    packet_in pkt,
    out H hdr,
    inout M user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md
);

control ChockVerifyChecksum<H, M>(
    inout H hdr,
    inout M user_meta
);

control ChockIngress<H, M>(
    inout H hdr,
    inout M user_meta,
    in chock_ingress_intrinsic_metadata_t ig_intr_md,
    out chock_ingress_to_egress_metadata_t ig_to_eg_md
);

control ChockTrafficManager<H, M>(
    inout H hdr,
    inout M user_meta,
    inout chock_ingress_to_egress_metadata_t ig_to_eg_md,
    out chock_egress_intrinsic_metadata_t eg_intr_md
);

control ChockEgress<H, M>(
    inout H hdr,
    inout M user_meta,
    in chock_egress_intrinsic_metadata_t eg_intr_md
);

control ChockComputeChecksum<H, M>(
    inout H hdr,
    inout M user_meta
);

control ChockDeparser<H>(
    packet_out pkt,
    in H hdr
);

/*
 * Top-Level ChockSwitch Architecture Package
 */
package ChockSwitch<H, M>(
    ChockParser<H, M> parser_inst,
    ChockVerifyChecksum<H, M> verify_checksum_inst,
    ChockIngress<H, M> ingress_inst,
    ChockTrafficManager<H, M> traffic_manager_inst,
    ChockEgress<H, M> egress_inst,
    ChockComputeChecksum<H, M> compute_checksum_inst,
    ChockDeparser<H> deparser_inst
);

#endif /* _CHOCK_ARCH_P4_ */
