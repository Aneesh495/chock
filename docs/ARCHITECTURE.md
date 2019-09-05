# Chock Architecture Specification

Chock is an ultra high performance programmable network data plane and in-network telemetry engine implemented in P4_16. It couples line-rate L2/L3 forwarding, Segment Routing over IPv6 (SRv6), and overlay virtualization with stateful traffic engineering, in-band telemetry vector stamping, hardware flow sketches, and in-network compute acceleration primitives.

## Pipeline Architecture

The Chock programmable switch architecture partitions data plane execution into distinct, deterministic stages across ingress, traffic management, and egress.

```mermaid
flowchart TD
    subgraph Ingress ["1. Ingress Processing Pipeline"]
        A["Physical Port PHY"] --> B["Packet Parser State Machine"]
        B --> C["Checksum Verification"]
        C --> D["TCAM ACL & Port Security"]
        D --> E["Counting Bloom Filter SYN Defense"]
        E --> F["4-Stage Count-Min Sketch"]
        F --> G["trTCM Token Bucket Policer"]
        G --> H{"In-Network Compute Intercept"}
        H -->|"NetCache Hit"| I1["Direct Read Cache Hit Reply"]
        H -->|"NetPaxos"| I2["Consensus Sequence Stamping"]
        H -->|"Market Feed"| I3["A/B Feed Line Arbitrator"]
        H -->|"Transit Traffic"| J["VLAN & Tunnel Decapsulation"]
        J --> K["SRv6 & MPLS Transport Engine"]
        K --> L["IPv4 / IPv6 LPM Routing & ECMP"]
        L --> M["Dynamic Flowlet Gap Switching"]
        M --> N["L2 Bridging & MAC Learning"]
        N --> O["INT Source Shim Encapsulation"]
    end

    subgraph TM ["2. Traffic Manager & Buffer Engine"]
        O --> P["Ingress Admission Control"]
        P --> Q["Virtual Output Queuing (VOQ)"]
        Q --> R["Deficit Round Robin Scheduler"]
        R --> S["Instantaneous Queue Depth & EWMA Estimation"]
    end

    subgraph Egress ["3. Egress Processing Pipeline"]
        S --> T["INT Transit Hop Metadata Stamping"]
        T --> U["Postcard Telemetry Microburst Trigger"]
        U --> V["RoCEv2 DCQCN Congestion Marking"]
        V --> W["Random Early Detection (RED) ECN Marking"]
        W --> X["Checksum Incremental Update"]
        X --> Y["Packet Deparser & Serialization"]
        Y --> Z["Egress Port MAC & PHY"]
    end
```

## Memory Hierarchy and Resource Allocation

Chock allocates on-chip hardware memory to optimize pipeline throughput and eliminate lookup stalls.

| Subsystem Component | Hardware Memory Type | Entry Capacity | Key Width | Lookup Latency |
| :--- | :--- | :--- | :--- | :--- |
| Ingress TCAM ACL | Ternary CAM | 8,192 rules | 12-tuple (288 bits) | 1 clock cycle |
| IPv4 FIB LPM | Algorithmic TCAM / Trie | 65,536 prefixes | 32-bit CIDR | 1 clock cycle |
| IPv6 FIB LPM | Algorithmic TCAM | 32,768 prefixes | 128-bit CIDR | 1 clock cycle |
| L2 Forwarding (FDB) | Hash-based SRAM | 16,384 entries | 60 bits (VLAN + MAC) | Single access |
| SRv6 SID Table | Hash-based SRAM | 8,192 entries | 128 bits | Single access |
| VXLAN / VNI Map | Hash-based SRAM | 4,096 entries | 24 bits | Single access |
| Flowlet Hash Table | Dual-ported SRAM | 65,536 flows | 16-bit CRC32 | Single access |
| Count-Min Sketch | 4x Multi-bank SRAM | 4 x 65,536 cells | 32-bit polynomial | Single access |
| Counting Bloom Filter | 2x Multi-bank SRAM | 2 x 65,536 bins | 16-bit Murmur3 | Single access |
| NetCache Storage | On-chip SRAM Registers | 16,384 slots | 64-bit key, 128-bit val | Single access |
| RoCEv2 QP Counters | Dual-ported SRAM | 65,536 queues | 24-bit QP ID | Single access |

## Latency Budget and Clock Cycles

At line rate (e.g., 400 Gbps to 3.2 Tbps per ASIC pipe), packet arrival interval is approximately 1.2 nanoseconds for 64-byte minimum frames. Chock maintains a deterministic execution latency of under 400 nanoseconds across the entire pipeline:

```mermaid
sequenceDiagram
    autonumber
    participant IngressPort as Ingress Port
    participant Parser as Multi-Protocol Parser
    participant IngressALU as Ingress Match-Action
    participant TM as Traffic Manager Queue
    participant EgressALU as Egress INT & Rewrite
    participant Deparser as Egress Deparser
    participant OutPort as Egress Port

    IngressPort->>Parser: Ingress Ethernet Frame (0.0 ns)
    Parser->>IngressALU: Parsed Header Stack (25.0 ns)
    IngressALU->>TM: Forwarding Decision & Metadata (120.0 ns)
    TM->>EgressALU: Queued Frame & Telemetry Vector (240.0 ns)
    EgressALU->>Deparser: Modified Headers & Hop Metadata (310.0 ns)
    Deparser->>OutPort: Serialized Wire Bits (360.0 ns)
```

## Checksum Recalculation Semantics

In accordance with RFC 1624, Chock avoids full packet rescans by calculating incremental checksum updates in P4 registers:

```
HC' = ~(~HC + ~m + m')
```

Where `HC` is the original checksum, `m` is the original field value (e.g. TTL or IPv4 address), and `m'` is the updated value. This guarantees zero-cost checksum adjustments in single-cycle ALU stages.
