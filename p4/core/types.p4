/*
 * Chock Core Types and Protocol Constants (P4_16)
 *
 * Comprehensive protocol type definitions, ether types, IP protocol numbers,
 * flags, status codes, and bitmask enumerations used throughout the data plane.
 */

#ifndef _CHOCK_CORE_TYPES_P4_
#define _CHOCK_CORE_TYPES_P4_

#include "../arch/chock_arch.p4"

/*
 * Standard Ethernet EtherType Constants (IEEE 802.3 / IANA)
 */
const bit<16> ETHERTYPE_IPV4          = 16#0800;
const bit<16> ETHERTYPE_ARP           = 16#0806;
const bit<16> ETHERTYPE_WOL           = 16#0842;
const bit<16> ETHERTYPE_RARP          = 16#8035;
const bit<16> ETHERTYPE_VLAN          = 16#8100;
const bit<16> ETHERTYPE_IPV6          = 16#86DD;
const bit<16> ETHERTYPE_FLOW_CONTROL  = 16#8808;
const bit<16> ETHERTYPE_SLOW_PROTOCOLS = 16#8809;
const bit<16> ETHERTYPE_MPLS_UNICAST  = 16#8847;
const bit<16> ETHERTYPE_MPLS_MULTICAST = 16#8848;
const bit<16> ETHERTYPE_PPPOE_DISCOVERY = 16#8863;
const bit<16> ETHERTYPE_PPPOE_SESSION  = 16#8864;
const bit<16> ETHERTYPE_JUMBO_FRAMES  = 16#8870;
const bit<16> ETHERTYPE_EAPOL         = 16#888E;
const bit<16> ETHERTYPE_PROFINET      = 16#8892;
const bit<16> ETHERTYPE_ETHERCAT      = 16#88A4;
const bit<16> ETHERTYPE_PROVIDER_VLAN = 16#88A8;
const bit<16> ETHERTYPE_GOOSE         = 16#88B8;
const bit<16> ETHERTYPE_GSE           = 16#88B9;
const bit<16> ETHERTYPE_SV            = 16#88BA;
const bit<16> ETHERTYPE_LLDP          = 16#88CC;
const bit<16> ETHERTYPE_SERCOS_III    = 16#88CD;
const bit<16> ETHERTYPE_WSMP          = 16#88DC;
const bit<16> ETHERTYPE_MRP           = 16#88E3;
const bit<16> ETHERTYPE_MACSEC        = 16#88E5;
const bit<16> ETHERTYPE_PTP           = 16#88F7;
const bit<16> ETHERTYPE_NC_SI         = 16#88F8;
const bit<16> ETHERTYPE_PRP           = 16#88FB;
const bit<16> ETHERTYPE_CFM           = 16#8902;
const bit<16> ETHERTYPE_FCOE          = 16#8906;
const bit<16> ETHERTYPE_ROCEV1        = 16#8915;
const bit<16> ETHERTYPE_TTE           = 16#891D;
const bit<16> ETHERTYPE_1905_1        = 16#893A;
const bit<16> ETHERTYPE_HSR           = 16#892F;

/*
 * IP Protocol Numbers (IANA IP Protocol Numbers Registry)
 */
const bit<8> IP_PROTO_HOPOPT         = 8#00;
const bit<8> IP_PROTO_ICMP           = 8#01;
const bit<8> IP_PROTO_IGMP           = 8#02;
const bit<8> IP_PROTO_GGP            = 8#03;
const bit<8> IP_PROTO_IPV4_ENCAP     = 8#04;
const bit<8> IP_PROTO_ST             = 8#05;
const bit<8> IP_PROTO_TCP            = 8#06;
const bit<8> IP_PROTO_CBT            = 8#07;
const bit<8> IP_PROTO_EGP            = 8#08;
const bit<8> IP_PROTO_IGP            = 8#09;
const bit<8> IP_PROTO_BBN_RCC_MON    = 8#0A;
const bit<8> IP_PROTO_NVP_II         = 8#0B;
const bit<8> IP_PROTO_PUP            = 8#0C;
const bit<8> IP_PROTO_ARGUS          = 8#0D;
const bit<8> IP_PROTO_EMCON          = 8#0E;
const bit<8> IP_PROTO_XNET           = 8#0F;
const bit<8> IP_PROTO_CHAOS          = 8#10;
const bit<8> IP_PROTO_UDP            = 8#11;
const bit<8> IP_PROTO_MUX            = 8#12;
const bit<8> IP_PROTO_DCN_MEAS       = 8#13;
const bit<8> IP_PROTO_HMP            = 8#14;
const bit<8> IP_PROTO_PRM            = 8#15;
const bit<8> IP_PROTO_XNS_IDP        = 8#16;
const bit<8> IP_PROTO_TRUNK_1        = 8#17;
const bit<8> IP_PROTO_TRUNK_2        = 8#18;
const bit<8> IP_PROTO_LEAF_1         = 8#19;
const bit<8> IP_PROTO_LEAF_2         = 8#1A;
const bit<8> IP_PROTO_RDP            = 8#1B;
const bit<8> IP_PROTO_IRTP           = 8#1C;
const bit<8> IP_PROTO_ISO_TP4        = 8#1D;
const bit<8> IP_PROTO_NETBLT         = 8#1E;
const bit<8> IP_PROTO_MFE_NSP        = 8#1F;
const bit<8> IP_PROTO_MERIT_INP      = 8#20;
const bit<8> IP_PROTO_DCCP           = 8#21;
const bit<8> IP_PROTO_3PC            = 8#22;
const bit<8> IP_PROTO_IDPR           = 8#23;
const bit<8> IP_PROTO_XTP            = 8#24;
const bit<8> IP_PROTO_DDP            = 8#25;
const bit<8> IP_PROTO_IDPR_CMTP      = 8#26;
const bit<8> IP_PROTO_TP_PP          = 8#27;
const bit<8> IP_PROTO_IL             = 8#28;
const bit<8> IP_PROTO_IPV6_ENCAP     = 8#29;
const bit<8> IP_PROTO_SDRP           = 8#2A;
const bit<8> IP_PROTO_IPV6_ROUTE     = 8#2B;
const bit<8> IP_PROTO_IPV6_FRAG      = 8#2C;
const bit<8> IP_PROTO_IDRP           = 8#2D;
const bit<8> IP_PROTO_RSVP           = 8#2E;
const bit<8> IP_PROTO_GRE            = 8#2F;
const bit<8> IP_PROTO_DSR            = 8#30;
const bit<8> IP_PROTO_BNA            = 8#31;
const bit<8> IP_PROTO_ESP            = 8#32;
const bit<8> IP_PROTO_AH             = 8#33;
const bit<8> IP_PROTO_I_NLSP         = 8#34;
const bit<8> IP_PROTO_SWIPE          = 8#35;
const bit<8> IP_PROTO_NARP           = 8#36;
const bit<8> IP_PROTO_MOBILE         = 8#37;
const bit<8> IP_PROTO_TLSP           = 8#38;
const bit<8> IP_PROTO_SKIP           = 8#39;
const bit<8> IP_PROTO_IPV6_ICMP      = 8#3A;
const bit<8> IP_PROTO_IPV6_NONXT     = 8#3B;
const bit<8> IP_PROTO_IPV6_OPTS      = 8#3C;
const bit<8> IP_PROTO_CFTP           = 8#3E;
const bit<8> IP_PROTO_SAT_EXPAK      = 8#40;
const bit<8> IP_PROTO_KRYPTOLAN      = 8#41;
const bit<8> IP_PROTO_RVD            = 8#42;
const bit<8> IP_PROTO_IPPC           = 8#43;
const bit<8> IP_PROTO_SAT_MON        = 8#45;
const bit<8> IP_PROTO_VISA           = 8#46;
const bit<8> IP_PROTO_IPCV           = 8#47;
const bit<8> IP_PROTO_CPNX           = 8#48;
const bit<8> IP_PROTO_CPHB           = 8#49;
const bit<8> IP_PROTO_WSN            = 8#4A;
const bit<8> IP_PROTO_PVP            = 8#4B;
const bit<8> IP_PROTO_BR_SAT_MON     = 8#4C;
const bit<8> IP_PROTO_SUN_ND         = 8#4D;
const bit<8> IP_PROTO_WB_MON         = 8#4E;
const bit<8> IP_PROTO_WB_EXPAK       = 8#4F;
const bit<8> IP_PROTO_ISO_IP         = 8#50;
const bit<8> IP_PROTO_VMTP           = 8#51;
const bit<8> IP_PROTO_SECURE_VMTP    = 8#52;
const bit<8> IP_PROTO_VINES          = 8#53;
const bit<8> IP_PROTO_TTP            = 8#54;
const bit<8> IP_PROTO_IPTM           = 8#54;
const bit<8> IP_PROTO_NSFNET_IGP     = 8#55;
const bit<8> IP_PROTO_DGP            = 8#56;
const bit<8> IP_PROTO_TCF            = 8#57;
const bit<8> IP_PROTO_EIGRP          = 8#58;
const bit<8> IP_PROTO_OSPF           = 8#59;
const bit<8> IP_PROTO_Sprite_RPC     = 8#5A;
const bit<8> IP_PROTO_LARP           = 8#5B;
const bit<8> IP_PROTO_MTP            = 8#5C;
const bit<8> IP_PROTO_AX_25          = 8#5D;
const bit<8> IP_PROTO_IPIP           = 8#5E;
const bit<8> IP_PROTO_MICP           = 8#5F;
const bit<8> IP_PROTO_SCC_SP         = 8#60;
const bit<8> IP_PROTO_ETHERIP        = 8#61;
const bit<8> IP_PROTO_ENCAP          = 8#62;
const bit<8> IP_PROTO_GMTP           = 8#64;
const bit<8> IP_PROTO_IFMP           = 8#65;
const bit<8> IP_PROTO_PNNI           = 8#66;
const bit<8> IP_PROTO_PIM            = 8#67;
const bit<8> IP_PROTO_ARIS           = 8#68;
const bit<8> IP_PROTO_SCPS           = 8#69;
const bit<8> IP_PROTO_QNX            = 8#6A;
const bit<8> IP_PROTO_A_N            = 8#6B;
const bit<8> IP_PROTO_IPComp         = 8#6C;
const bit<8> IP_PROTO_SNP            = 8#6D;
const bit<8> IP_PROTO_Compaq_Peer    = 8#6E;
const bit<8> IP_PROTO_IPX_IN_IP      = 8#6F;
const bit<8> IP_PROTO_VRRP           = 8#70;
const bit<8> IP_PROTO_PGM            = 8#71;
const bit<8> IP_PROTO_L2TP           = 8#73;
const bit<8> IP_PROTO_DDX            = 8#74;
const bit<8> IP_PROTO_IATP           = 8#75;
const bit<8> IP_PROTO_STP            = 8#76;
const bit<8> IP_PROTO_SRP            = 8#77;
const bit<8> IP_PROTO_UTI            = 8#78;
const bit<8> IP_PROTO_SMP            = 8#79;
const bit<8> IP_PROTO_SM             = 8#7A;
const bit<8> IP_PROTO_PTP_IP         = 8#7B;
const bit<8> IP_PROTO_ISIS_OVER_IPV4 = 8#7C;
const bit<8> IP_PROTO_FIRE           = 8#7D;
const bit<8> IP_PROTO_CRTP           = 8#7E;
const bit<8> IP_PROTO_CRUDP          = 8#7F;
const bit<8> IP_PROTO_SSCOPMCE       = 8#80;
const bit<8> IP_PROTO_IPLT           = 8#81;
const bit<8> IP_PROTO_SPS            = 8#82;
const bit<8> IP_PROTO_PIPE           = 8#83;
const bit<8> IP_PROTO_SCTP           = 8#84;
const bit<8> IP_PROTO_FC             = 8#85;
const bit<8> IP_PROTO_RSVP_E2E_IGNORE = 8#86;
const bit<8> IP_PROTO_MOBILITY_HEADER = 8#87;
const bit<8> IP_PROTO_UDPLITE        = 8#88;
const bit<8> IP_PROTO_MPLS_IN_IP     = 8#89;
const bit<8> IP_PROTO_MANET          = 8#8A;
const bit<8> IP_PROTO_HIP            = 8#8B;
const bit<8> IP_PROTO_SHIM6          = 8#8C;
const bit<8> IP_PROTO_WESP           = 8#8D;
const bit<8> IP_PROTO_ROHC           = 8#8E;
const bit<8> IP_PROTO_ETHERNET_IN_IP = 8#8F;
const bit<8> IP_PROTO_AGGFRAG        = 8#90;

/*
 * Well-Known Transport Port Numbers
 */
const bit<16> UDP_PORT_DNS          = 53;
const bit<16> UDP_PORT_DHCP_SERVER  = 67;
const bit<16> UDP_PORT_DHCP_CLIENT  = 68;
const bit<16> UDP_PORT_TFTP         = 69;
const bit<16> UDP_PORT_NTP          = 123;
const bit<16> UDP_PORT_SNMP         = 161;
const bit<16> UDP_PORT_SNMP_TRAP    = 162;
const bit<16> UDP_PORT_BGP          = 179;
const bit<16> UDP_PORT_PTP_EVENT    = 319;
const bit<16> UDP_PORT_PTP_GENERAL  = 320;
const bit<16> UDP_PORT_RIP          = 520;
const bit<16> UDP_PORT_DHCPV6_CLIENT = 546;
const bit<16> UDP_PORT_DHCPV6_SERVER = 547;
const bit<16> UDP_PORT_SYSLOG       = 514;
const bit<16> UDP_PORT_L2TP         = 1701;
const bit<16> UDP_PORT_RADIUS_AUTH  = 1812;
const bit<16> UDP_PORT_RADIUS_ACCT  = 1813;
const bit<16> UDP_PORT_GTP_C        = 2123;
const bit<16> UDP_PORT_GTP_U        = 2152;
const bit<16> UDP_PORT_BFD_CONTROL  = 3784;
const bit<16> UDP_PORT_BFD_ECHO     = 3785;
const bit<16> UDP_PORT_IPSEC_NAT_T  = 4500;
const bit<16> UDP_PORT_VXLAN        = 4789;
const bit<16> UDP_PORT_ROCEV2       = 4791;
const bit<16> UDP_PORT_GENEVE       = 6081;
const bit<16> UDP_PORT_SFLOW        = 6343;
const bit<16> UDP_PORT_NETCACHE     = 8888;
const bit<16> UDP_PORT_NETPAXOS     = 9999;
const bit<16> UDP_PORT_MARKET_FEED_A = 10001;
const bit<16> UDP_PORT_MARKET_FEED_B = 10002;
const bit<16> UDP_PORT_INT_REPORT   = 11111;

/*
 * Well-Known TCP Port Numbers
 */
const bit<16> TCP_PORT_ECHO         = 7;
const bit<16> TCP_PORT_FTP_DATA     = 20;
const bit<16> TCP_PORT_FTP_CONTROL  = 21;
const bit<16> TCP_PORT_SSH          = 22;
const bit<16> TCP_PORT_TELNET       = 23;
const bit<16> TCP_PORT_SMTP         = 25;
const bit<16> TCP_PORT_TACACS       = 49;
const bit<16> TCP_PORT_DNS          = 53;
const bit<16> TCP_PORT_HTTP         = 80;
const bit<16> TCP_PORT_POP3         = 110;
const bit<16> TCP_PORT_IDENT        = 113;
const bit<16> TCP_PORT_NNTP         = 119;
const bit<16> TCP_PORT_NTP          = 123;
const bit<16> TCP_PORT_NETBIOS_SSN  = 139;
const bit<16> TCP_PORT_IMAP         = 143;
const bit<16> TCP_PORT_BGP          = 179;
const bit<16> TCP_PORT_LDAP         = 389;
const bit<16> TCP_PORT_HTTPS        = 443;
const bit<16> TCP_PORT_SMB          = 445;
const bit<16> TCP_PORT_RTSP         = 554;
const bit<16> TCP_PORT_LDAPS        = 636;
const bit<16> TCP_PORT_P4RUNTIME    = 9559;

/*
 * TCP Control Flags Bitmasks
 */
const bit<8> TCP_FLAG_FIN = 8#01;
const bit<8> TCP_FLAG_SYN = 8#02;
const bit<8> TCP_FLAG_RST = 8#04;
const bit<8> TCP_FLAG_PSH = 8#08;
const bit<8> TCP_FLAG_ACK = 8#10;
const bit<8> TCP_FLAG_URG = 8#20;
const bit<8> TCP_FLAG_ECE = 8#40;
const bit<8> TCP_FLAG_CWR = 8#80;

/*
 * DSCP (Differentiated Services Code Point) Definitions
 */
const bit<6> DSCP_CS0  = 6#00;
const bit<6> DSCP_CS1  = 6#08;
const bit<6> DSCP_CS2  = 6#10;
const bit<6> DSCP_CS3  = 6#18;
const bit<6> DSCP_CS4  = 6#20;
const bit<6> DSCP_CS5  = 6#28;
const bit<6> DSCP_CS6  = 6#30;
const bit<6> DSCP_CS7  = 6#38;

const bit<6> DSCP_AF11 = 6#0A;
const bit<6> DSCP_AF12 = 6#0C;
const bit<6> DSCP_AF13 = 6#0E;

const bit<6> DSCP_AF21 = 6#12;
const bit<6> DSCP_AF22 = 6#14;
const bit<6> DSCP_AF23 = 6#16;

const bit<6> DSCP_AF31 = 6#1A;
const bit<6> DSCP_AF32 = 6#1C;
const bit<6> DSCP_AF33 = 6#1E;

const bit<6> DSCP_AF41 = 6#22;
const bit<6> DSCP_AF42 = 6#24;
const bit<6> DSCP_AF43 = 6#26;

const bit<6> DSCP_EF   = 6#2E;
const bit<6> DSCP_VOICE_ADMIT = 6#2C;

/*
 * Explicit Congestion Notification (ECN) Codepoints
 */
const bit<2> ECN_NOT_ECT = 2#00;
const bit<2> ECN_ECT_1   = 2#01;
const bit<2> ECN_ECT_0   = 2#10;
const bit<2> ECN_CE      = 2#11;

/*
 * ARP Operation Codes
 */
const bit<16> ARP_OP_REQUEST        = 1;
const bit<16> ARP_OP_REPLY          = 2;
const bit<16> ARP_OP_RREQUEST       = 3;
const bit<16> ARP_OP_RREPLY         = 4;
const bit<16> ARP_OP_DRARPREQUEST   = 5;
const bit<16> ARP_OP_DRARPREPLY     = 6;
const bit<16> ARP_OP_DRARPERROR     = 7;
const bit<16> ARP_OP_INARPREQUEST   = 8;
const bit<16> ARP_OP_INARPREPLY     = 9;

/*
 * ICMPv4 Message Types
 */
const bit<8> ICMPV4_TYPE_ECHO_REPLY          = 0;
const bit<8> ICMPV4_TYPE_DEST_UNREACHABLE    = 3;
const bit<8> ICMPV4_TYPE_SOURCE_QUENCH       = 4;
const bit<8> ICMPV4_TYPE_REDIRECT            = 5;
const bit<8> ICMPV4_TYPE_ECHO_REQUEST        = 8;
const bit<8> ICMPV4_TYPE_ROUTER_ADVERT       = 9;
const bit<8> ICMPV4_TYPE_ROUTER_SOLICIT      = 10;
const bit<8> ICMPV4_TYPE_TIME_EXCEEDED       = 11;
const bit<8> ICMPV4_TYPE_PARAM_PROBLEM       = 12;
const bit<8> ICMPV4_TYPE_TIMESTAMP           = 13;
const bit<8> ICMPV4_TYPE_TIMESTAMP_REPLY     = 14;

/*
 * ICMPv6 Message Types
 */
const bit<8> ICMPV6_TYPE_DEST_UNREACHABLE    = 1;
const bit<8> ICMPV6_TYPE_PACKET_TOO_BIG      = 2;
const bit<8> ICMPV6_TYPE_TIME_EXCEEDED       = 3;
const bit<8> ICMPV6_TYPE_PARAM_PROBLEM       = 4;
const bit<8> ICMPV6_TYPE_ECHO_REQUEST        = 128;
const bit<8> ICMPV6_TYPE_ECHO_REPLY          = 129;
const bit<8> ICMPV6_TYPE_ROUTER_SOLICIT      = 133;
const bit<8> ICMPV6_TYPE_ROUTER_ADVERT       = 134;
const bit<8> ICMPV6_TYPE_NEIGHBOR_SOLICIT    = 135;
const bit<8> ICMPV6_TYPE_NEIGHBOR_ADVERT     = 136;

#endif /* _CHOCK_CORE_TYPES_P4_ */\n