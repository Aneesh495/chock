# Segment Routing over IPv6 (SRv6) Specification in Chock

Chock implements full RFC 8754 and RFC 8986 Segment Routing over IPv6 (SRv6) Network Programming primitives. SRv6 encodes network instructions (Segments) directly into 128-bit IPv6 destination addresses and chained Segment Routing Headers (SRH).

## SRv6 SID Architecture

Each 128-bit Segment Identifier (SID) is structured as follows:

```
+---------------------------+-------------------+----------------------+
|       Locator (B bits)    |  Function (F bits)|   Arguments (A bits) |
+---------------------------+-------------------+----------------------+
|<--------------------------- 128 bits ------------------------------->|
```

- **Locator (B bits)**: Routes the packet through standard IPv6 routing infrastructure to the node executing the function. Typical length is 48 to 64 bits.
- **Function (F bits)**: Identifies the specific data plane behavior bound to this SID (e.g., End, End.X, End.DT4, End.DT6).
- **Arguments (A bits)**: Optional metadata or parameters passed to the function (e.g., target tenant VRF, interface index, flow label).

## Endpoint Behaviors Implemented

### 1. End (Endpoint Execution)
RFC 8986 Section 4.1: The basic endpoint function. When a packet arrives with the switch's local SID as the IPv6 destination address and `Segments Left > 0`:
1. Decrements `Segments Left` by 1.
2. Updates `IPv6 Destination Address` with `Segment List[Segments Left]`.
3. Forwards the packet via standard IPv6 FIB lookup.

### 2. End.X (Endpoint with Layer 3 Cross-Connect)
RFC 8986 Section 4.2: Endpoint bound to a specific outgoing Layer 3 adjacency.
1. Decrements `Segments Left` by 1.
2. Updates `IPv6 Destination Address` with `Segment List[Segments Left]`.
3. Forwards directly to the bound next-hop MAC and port, bypassing FIB lookup.

### 3. End.DT4 (Endpoint with Decapsulation and IPv4 VRF Table Lookup)
RFC 8986 Section 4.7: Used for IPv4 L3VPN and multi-tenant overlay networks.
1. Validates that `Segments Left == 0`.
2. Strips the outer IPv6 header, SRH, and SID stack.
3. Sets the packet VRF context to the tenant VRF mapped to the Function bits.
4. Forwards inner IPv4 payload through tenant routing table.

### 4. End.DT6 (Endpoint with Decapsulation and IPv6 VRF Table Lookup)
RFC 8986 Section 4.8: Used for IPv6 L3VPN overlay networks.
1. Validates that `Segments Left == 0`.
2. Strips the SRH and SID stack.
3. Binds inner IPv6 packet to the tenant VRF.
4. Forwards through tenant IPv6 FIB.

### 5. T.Encap (Transit Encapsulation)
Encapsulates non-SRv6 traffic entering the domain at the ingress edge node:
1. Pushes outer IPv6 header.
2. Inserts Segment Routing Header (SRH) with ordered segment list `[SID_0, SID_1, ..., SID_k]`.
3. Sets outer destination address to first segment in the path.

## Segment Routing Flavors

Chock supports three standard next-hop execution flavors:
- **PSP (Penultimate Segment Popping)**: The penultimate router pops the SRH when `Segments Left == 1` to reduce packet overhead at the destination node.
- **USP (Ultimate Segment Popping)**: The destination node pops the SRH when `Segments Left == 0` while retaining the outer IPv6 header.
- **USD (Ultimate Segment Decapsulation)**: The destination node decapsulates the entire outer IPv6 header and SRH upon completing the segment sequence.
