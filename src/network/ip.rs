use std::{fmt::Debug, mem::transmute, ops::AddAssign};

use m6tobytes::*;
use strum::{EnumIter, IntoEnumIterator};

use super::{IPv4Addr, InetCkSum, inet_cksum};
use crate::be::U16Be;

////////////////////////////////////////////////////////////////////////////////
//// Structures

/// IP Header Length & Version (IPv4)
#[derive(Clone, Copy, PartialEq, Eq, Hash, ToBytes, FromBytes)]
#[repr(transparent)]
pub struct IHLAndVer(u8);

/// (origin) Type of Service
#[derive(Clone, Copy, PartialEq, Eq, Hash, FromBytes, ToBytes)]
#[repr(transparent)]
pub struct ToS(u8);

///
/// [Differenciated services](https://en.wikipedia.org/wiki/Differentiated_services) compared with
/// [Integrated services](https://en.wikipedia.org/wiki/Integrated_services) which is
/// flow-based, fine-grained (trace each stream) QoS system, is
/// class-based (just devide streams into difference class) and coarse-grained.
///
/// ## Integrated services
///
/// Under IntServ, every router in the system implements IntServ, and every application that requires
/// some kind of QoS guarantee has to make an individual reservation.
///
/// Flow specs describe what the reservation is for, while
/// [RSVP](https://en.wikipedia.org/wiki/Resource_Reservation_Protocol) is the underlying mechanism to signal
/// it across the network.
///
/// ### TSPEC
///
/// Traffic Specification part, using [token bucket algorithms](https://en.wikipedia.org/wiki/Token_bucket) parameters:
///
/// the token rate and the bucket depth.
///
/// ### RSPEC
///
/// RSPECs specify what requirements there are for the flow.
///
/// + **best effort** in which case no reservation is needed.
///
/// + **Controlled Load** mirrors the performance of a lightly loaded network:
/// there may be occasional glitches when two people access the same resource by chance,
/// but generally both delay and drop rate are fairly constant at the desired rate.
/// This setting is likely to be used by soft QoS applications.
///
/// + **Guaranteed** gives an absolutely bounded service, where the delay is promised
/// to never go above a desired amount, and packets never dropped, provided the traffic
/// stays within spec.
///
/// #### RSVP
///
/// RSVP(Resource Reservation Protocol) is Transport Layer designed to reserve resources across a network for the
/// integrated services model.
///
/// All machines on the network capable of sending QoS data send a PATH message every 30 seconds, which spreads out
/// through the networks. Those who want to listen to them send a corresponding RESV (short for "Reserve") message which
/// then traces the path backwards to the sender. The RESV message contains the flow specs.
///
/// The routers between the sender and listener have to decide if they can support the reservation being requested,
/// and if they cannot, they send a reject message to let the listener know about it.
/// Otherwise, once they accept the reservation they have to carry the traffic.
///
/// ## Differenciated services
///
/// Today, DiffServ has largely supplanted TOS and other layer-3 QoS mechanisms, such as integrated services (IntServ),
/// as the primary architecture routers use to provide QoS.
///
#[derive(Clone, Copy, PartialEq, Eq, Hash, FromBytes, ToBytes)]
#[derive_to_bits(u8)]
#[repr(transparent)]
pub struct DS(u8);

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
#[derive_to_bits_into(DS)]
#[derive_to_bits(u8)]
#[repr(u8)]
pub enum DSCP {
    /// Default Forwarding (CS0)
    ///
    #[default]
    DF = 0,
    /// Lower-effort
    LE = 1,
    /// Expedited Forwarding
    EF = 46,
    VoiceAdmit = 44,
    AF11 = 10,
    AF12 = 12,
    AF13 = 14,
    AF21 = 18,
    AF22 = 20,
    AF23 = 22,
    AF31 = 26,
    AF32 = 28,
    AF33 = 30,
    AF41 = 34,
    AF42 = 36,
    AF43 = 38,
    CS1 = 8,
    CS2 = 16,
    CS3 = 24,
    CS4 = 32,
    CS5 = 40,
    CS6 = 48,
    CS7 = 56,
    Undefined(u8),
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum ServiceClass {
    Lowlatency(DropProb),
    Highthrouput(DropProb),
    NetworkControl,
    Telephony,
    Signaling,
    MultimediaConferencing(DropProb),
    RealtimeInteractive,
    MultimediaStreaming(DropProb),
    BroadcastVideo,
    /// Network operations administration and maintenance (OA&M)
    OAM,
    Standard,
    LowerEffort,
    Undefined(u8),
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[repr(u8)]
pub enum DropProb {
    Low = 1,
    Medium = 2,
    High = 3,
}

/// Explicit Congestion Notification (occupies low 2 bits)
///
/// ECT0 vs ECT1, reference: https://www.rfc-editor.org/rfc/rfc3168.html#page-55
///
/// (supply one bit nonce)
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
#[derive_to_bits(u8)]
#[repr(u8)]
pub enum ECN {
    /// Not ECT-Capable Transport
    #[default]
    NotECT = 0,
    /// 0b01
    ECT1,
    /// default ECT value, 0b10
    ECT0,
    /// Congestion Experienced, 0b11
    ///
    /// modify the ECT0 or ETC1 to CE
    CE,
}

/// Datagram (header + data) length
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct TotLen(U16Be);

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct Id(U16Be);

#[derive(Clone, Copy, PartialEq, Eq, Hash, FromBytes, ToBytes)]
#[derive_to_bits(u16)]
#[repr(transparent)]
pub struct FlagsAndOff(u16);

/// low 13 bit in units of 8 bytes
#[derive(Clone, Copy, PartialEq, Eq, Hash, FromBytes, ToBytes, Default)]
#[repr(transparent)]
pub struct FragOff(u16);

#[derive(Clone, Copy, PartialEq, Eq, Hash, EnumIter, Debug, Default)]
#[derive_to_bits(u8)]
#[repr(u8)]
pub enum FragFlag {
    /// Don't Fragment, If the DF flag is set, and fragmentation is required
    /// to route the packet, then the packet is dropped.
    #[default]
    DF = 0b010,
    /// More Fragments, For unfragmented packets, the MF flag is cleared.
    ///
    /// For fragmented packets, all fragments except the last have the MF flag set.
    /// The last fragment has a non-zero Fragment Offset field, so it can still be
    /// differentiated from an unfragmented packet.
    MF = 0b001,
}

/// Time to lives: hop limit for ip packet
#[derive(Clone, Copy, PartialEq, Eq, Hash, FromBytes, ToBytes, Debug)]
#[derive_to_bits(u8)]
#[repr(transparent)]
pub struct TTL(u8);

#[derive(Clone, Copy, PartialEq, Eq, Hash, FromBytes, ToBytes)]
#[derive_to_bits(u8)]
#[derive_from_bits(u8)]
#[repr(transparent)]
pub struct Protocol(u8);

/// Refer [IANA protocol numbers](https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml)
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
#[derive_to_bits_into(Protocol)]
#[derive_to_bits(u8)]
#[repr(u8)]
pub enum ProtocolKind {
    /// 0x00 IPv6 Hop by Hop Options
    #[default]
    HopOpt,
    /// 0x01 Internet Control Message Protocol
    ICMP,
    /// 0x02 Interet Group Management Protocol
    ///
    /// used by hosts and adjacent routers on IPv4 networks
    /// to establish multicast group memberships.
    ///
    /// (on IPv6. it's MLD)
    IGMP,
    /// 0x03 Obsolete, give way to EGP.
    ///
    /// Gateway-to-Gateway Protocol,
    GGP,
    /// 0x04 Encapulate IP packet into another IP packet
    IPinIP,
    /// 0x05 Internet Stream Protocol (IPv5, obsolete)
    ST,
    /// 0x06
    TCP,
    /// 0x07 Core-based trees
    ///
    /// a proposal for making IP Multicast scalable
    /// by constructing a tree of routers.
    CBT,
    /// 0x08 Replacement of GGP
    EGP,
    /// 0x09 Interior gateway protocol
    ///
    /// Routing protocol used for exchanging routing table information
    /// between gateways within an autonomous system.
    ///
    /// Including distance-vector routing protocols, link-state routing protocols
    ///
    IGP,
    /// 0x0A BBN RCC Monitoring
    BbnRccMonitoring,
    /// 0x0B Network Voice Protocol v2
    NVP2,
    /// 0x0C PARC Universal Packet, one of two earliest internetworking protocol suite.
    PUP,
    /// 0x0D
    ARGUS,
    /// 0x0E
    EMCON,
    /// 0x0F Cross Net Debugger
    XNET,
    /// 0x10 Chaosnet, early developed local area network technology
    CHAOS,
    /// 0x11
    UDP,
    /// 0x12 Multiplexing
    MUX,
    /// 0x13 DCN Measurement Subsystems
    DCNMeas,
    /// 0x14 Host Monitoring Protocol
    ///
    /// an obsolete TCP/IP protocol
    HMP,
    /// 0x15 Packet Radio Measurement
    PRM,
    /// 0x16 XEROX NS IDP
    XNSIDP,
    /// 0x17
    Trunk1,
    /// 0x18
    Trunk2,
    /// 0x19
    Leaf1,
    /// 0x1A
    Leaf2 = 0x1A,
    /// 0x1B Reliable Data Protocol
    ///
    /// provide facilities for remote loading, debuging
    /// and bulking transfer of images and data.
    ///
    /// Transport Layer Protocol, only experimental implementations for BSD exist
    RDP,
    /// 0x1C Iternet Reliable Transaction Protocol
    IPTP,
    /// 0x1D ISO Transport Protocol Class 4
    ISOTP4,
    /// 0x1E Bulk Data Transfer Protocol
    NETBLT,
    /// 0x1F MFE Networking Services Protocol
    MFENSP,
    /// 0x20 MERIT Internodal Protocol
    MERITINP,
    /// 0x21 Datagram Congestion Control Protocol
    DCCP,
    /// 0x22 Third Party Connection Protocol
    ThirdPC,
    /// 0x23 Inter-Domain Policy Routing Protocol
    IDPR,
    /// 0x24 Xpress Transport Protocol
    ///
    /// Transport layer protocol, developed to replace TCP
    XTP,
    /// 0x25 Datagram Delivery Protocol
    ///
    /// member of the Apple Talk networking protocol suite, Its main responsibility
    /// is for socket-to-socket delivery of datagrams over AppleTalk network.
    DDP,
    /// 0x26 IDPR Control Message Transport Protocol
    IDPRCMTP,
    /// 0x27
    TPPlusPlus,
    /// 0x28 Internet Link, similiar but much simpler than TCP
    IL,
    /// 0x29 IPv6 Encapsulation
    IPv6,
    /// 0x2A Source Demand Routing Protocol
    SDRP,
    /// 0x2B Routing Header for IPv6
    IPv6Route,
    /// 0x2C Fragment Header for IPv6
    IPv6Frag,
    /// 0x2D Inter-Domain Routing Protocol
    IDRP,
    /// 0x2E Resource Reservation Protocol
    RSVP,
    /// 0x2F Generic Routing Encapsulation
    ///
    /// Developed by Cisco system that encapsulates a wide variety
    /// of network layer protocols inside virtual point2point links or
    /// point2multipoint links.
    GRE,
    /// 0x30 Dynamic Source Routing Protocol
    ///
    /// routing protocol for wireless mesh networks
    DSR,
    /// 0x31 Burroughs Network Architecure
    BNA,
    /// 0x32 Encapsulating Security Payload
    ESP,
    /// 0x33 Authentication Header
    AH,
    /// 0x34 Integrated Net Layer Security Protocol
    INLSP,
    /// 0x35 swlPe IP Security Protocol
    SWIPE,
    /// 0x36 NBMA Address Resolution Protocol
    NARP,
    /// 0x37 IP Mobility
    ///
    /// Makes mobile device move from one network
    /// to another mantaining a permanent IP address.
    MOBILE,
    /// 0x38 Transport Layer Security Protocol (TLS)
    TLSP,
    /// 0x39 Simple Key-Management for Internet Protocol
    SKIP,
    /// 0x3A ICMP for IPv6
    IPv6ICMP,
    /// 0x3B No Next Header for IPv6
    IPv6NoNxt,
    /// 0x3C Destination Options for IPv6
    IPv6Opts,
    /// 0x3D Any Host Internet Protocol
    AnyHostIP,
    /// 0x3E
    CFTP,
    /// 0x3F Any Local Network
    AnyLocalNet,
    /// 0x40 SATNET and Backroom EXPAK
    SATEXPACT,
    /// 0x46 VISA Protocol
    VISA,
    /// 0x47 Internet Packet Core Utility
    IPCU,
    /// 0x48 Computer Protocol Network Executive
    CPNX,
    /// 0x49 Computer Protocol Heart Beat
    CPHB,
    /// 0x4A Wang Span Network
    WSN,
    /// 0x4B Packet Video Protocol
    PVP,
    /// 0x4C Backroom SATNET Monitoring
    BrSatMon,
    /// 0x4D SUN ND Protocol-Temporary
    SunNd,
    /// 0x4E Wideband Monitoring
    WbMon,
    /// 0x4F Wideband Expack
    WbExpak,
    /// 0x50 International Organization for Standardization Internetr Protocol
    ISOIP,
    /// 0x51 Versatile Message Transaction Protocol
    VMTP,
    /// 0x52 Secure Versatile Message Transaction Protocol
    SecureVMTP,
    /// 0x53 VINES
    VINES,
    /// 0x54
    ///
    /// TTP, Time-Triggered Protocol, computer network protocol for control systems
    ///
    /// IPTM, Internet Protocol Traffic Manager
    ///
    /// TTP or IPTM, It depends.
    TTPOrIPTM,
    /// 0x55 NSFNET-IGP
    NSFNetIGP,
    /// 0x56 Dissimiliar Protocol Traffic Manager
    DGP,
    /// 0x57
    TCF,
    /// 0x58 Enhanced Interior Gateway Routing Protocol,
    ///
    /// advanced distance-vector routing protocol used for automating routing
    /// decisions and configuration. From Cisco System proprietary protocol
    /// to Open Standard.
    EIGRP,
    /// 0x59 Open Shortest Path First, routing protocol for Internet Protocol networks.
    OSPF,
    /// 0x5A Sprite RPC Protocol
    SpriteRPC,
    /// 0x5B Locus Address Resolution Protocol
    LARP,
    /// 0x5C Multiacst Transport Protocol
    MTP,
    /// 0x5D data link layer protocol (such asunder the IPv4/TCP)
    ///
    /// AX.25 has most frequently been used to establish direct, point-to-point
    /// links between packet radio stations, without any additional network layers.
    AX25,
    /// 0x5E KA9Q NOS compatiable IP over IP tunneling
    OS,
    /// 0x5F Mobile internetworking Control Protocol
    MICP,
    /// 0x60 Semaphore Communications Sec. Pro
    SCCSP,
    /// 0x61 Ethernet within IP Encapsulation
    EtheRip,
    /// 0x62 Encapsulation Header
    EnCap,
    /// 0x63
    AnyPrivateEncryptionScheme,
    /// 0x64
    GMTP,
    /// 0x65 Ipsilon Flow Management Protocol
    IFMP,
    /// 0x66 PNNI over IP
    PNNI,
    /// 0x67 Protocol Independent Multicast
    ///
    /// a family of multicast routing protocols for Internet Protocol (IP) networks
    /// that provide one-to-many and many-to-many distribution of data over a LAN,
    /// WAN or the Internet.
    PIM,
    /// 0x68 IBM's ARIS (Aggregate Route IP Switching) Protocol
    ARIS,
    /// 0x69 Space Communications Protocol Standards
    SCPS,
    /// 0x6A
    QNX,
    /// 0x6B Active Networks
    AN,
    /// 0c6C IP Payload Compression Protocol
    ///
    /// low level compression protocol for IP datagrams, can work with both TCP and UDP
    IPComp,
    /// 0x6D Sitara Networks Protocol
    SNP,
    /// 0x6E Compaq Peer Protocol
    CompaqPeer,
    /// 0x6F IPX in IP
    IPXinIP,
    /// 0x70 Virtual Router Redundancy Protocol
    ///
    /// Supply creation of virual routers
    VRRP,
    /// 0x71 Pragmatic General Multicast
    PGM,
    /// 0x72 Any 0-hop protocol
    Any0Hop,
    /// 0x73 Layer 2 Tunneling Protocol Version 3
    ///
    /// simplified version of MPLS
    L2TP,
    /// 0x74 D-2 Data Exchange
    DDX,
    /// 0x75 Interactive Agent transfer Protocol
    IATP,
    /// 0x76 Schedule Transfer Protocol
    STP,
    /// 0x77 SpetraLink Radio Protocol
    SRP,
    /// 0x78 Universal Transport Interface Protocol
    UTI,
    /// 0x79 Simple Message Protocol
    SMP,
    /// 0x7A
    SM,
    /// 0x7B Performance Transparency Protocol
    PTP,
    /// 0x7C Intermediate System to Intermediate System Protocol over IPv4
    ISISIPv4,
    /// 0x7D  Flexiable Intra-AS Routing Environment
    FIRE,
    /// 0x7E Combat Radio Transport Protocol
    CRTP,
    /// 0x7F Combat User Datagram
    CRUDP,
    /// 0x80 Service-Specific Connection-Oriented Protocol
    /// in a Multilink and Connectionless Environment
    SSCOPMCE,
    /// 0x81
    IPLT,
    /// 0x82 Secure Packet Shield
    SPS,
    /// 0x83 Private IP Encapsulation within IP
    PIPE,
    /// 0x84 Stream Control Transmission Protocol
    ///
    /// transport layer protocol, providing message oriented for UDP
    SCTP,
    /// 0x85 Fibre Channel
    ///
    /// high-speed data transfer protocol providing in-order, lossless delivery
    /// of raw block data
    FC,
    /// 0x86 Reservation Protocol (RSVP) End-to-End Ignore
    RsvpE2eIgnore,
    /// 0x87 Mobility Header for IPv6
    MobiHdr,
    /// 0x88 Lightweight UDP
    UDPLite,
    /// 0x89 Multiprotocol Label Switching Encapsulated in IP
    MPLSInIP,
    /// 0x8A wireless (mobile) ad hoc network
    Manet,
    /// 0x8B Host Identity Protocol
    ///
    /// HIP separates the end-point identifier and locator roles of IP
    /// addresses.
    /// It introduces a Host Identity (HI) name space, based on a public key security infrastructure.
    HIP,
    /// 0x8C Site Multihoming by IPv6
    Shim6,
    /// 0x8D Wrapped Encapsulating Security Payload
    WESP,
    /// 0x8E Robust Header Compression
    ///
    /// standardized method to compress IP, UDP, UDPLite,
    /// RTP(Relatime Transport Protocol), TCP header
    ROHC,
    /// 0x8F Temporary, IPv6 Segment Routing
    Ethernet,
    /// AGGFRAG Encapsulation Payload for ESP
    AGGFRAG = 0x90,
    /// Network Service Header
    NSH = 0x91,
    // 0x92-0xFC (146-252) unassigned value
    Unassigned(u8),
    /// 0xFD-0xFE 253-254
    Test(u8),
    /// or Raw
    Reserved = 0xFF,
}

///
/// IPv4 Diagram Header (20 bytes)
///
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[repr(C)]
pub struct IPv4 {
    pub ihl_v: IHLAndVer,
    pub tos: ToS,
    pub totlen: TotLen,
    pub id: Id,
    pub flags_off: FlagsAndOff,
    pub ttl: TTL,
    pub proto: Protocol,
    /// Check: IPv4 header
    ///
    /// While computing the checksum, the checksum field itself is cleared.
    pub cksum: InetCkSum,
    pub src: IPv4Addr,
    pub dst: IPv4Addr,
}

/// IPv4 pseudo header for checksum
#[derive(Clone, Copy, PartialEq, Eq, Hash, FromBytes, ToBytes)]
#[repr(packed)]
#[repr(C)]
pub struct PseudoHeader {
    pub src: IPv4Addr,
    pub dst: IPv4Addr,
    pub zeros: u8,
    pub proto: Protocol,
    /// The length of the payload (such as length of TCP/UDP header and data).
    pub payload_len: u16,
}

////////////////////////////////////////////////////////////////////////////////
//// Implementations

impl IPv4 {
    pub fn pseudo_header(&self, payload_len: u16) -> PseudoHeader {
        PseudoHeader {
            src: self.src,
            dst: self.dst,
            zeros: 0,
            proto: self.proto,
            payload_len,
        }
    }

    pub fn checksummed(mut self) -> Self {
        self.cksum = Default::default();
        self.cksum = inet_cksum(self.as_buf()).into();

        self
    }

    pub fn verify_cksum(&self) -> bool {
        inet_cksum(self.as_buf()) == 0
    }

    pub fn as_buf(&self) -> &[u8] {
        as_raw_slice(self)
    }
}

impl From<Protocol> for ProtocolKind {
    fn from(value: Protocol) -> Self {
        Self::from(value.0)
    }
}

impl From<u8> for ProtocolKind {
    fn from(value: u8) -> Self {
        match value {
            146..=252 => Self::Unassigned(value),
            253 | 254 => Self::Test(value),
            255 => Self::Reserved,
            _ => unsafe { transmute(value as u16) },
        }
    }
}

impl Default for TTL {
    fn default() -> Self {
        Self(64)
    }
}

impl FragOff {
    /// * 8 bytes
    pub fn len(&self) -> usize {
        (self.0 as usize) << 3
    }

    pub fn new_with_len(len: usize) -> Self {
        debug_assert!(len % 8 == 0);

        Self((len >> 8) as _)
    }
}

impl Debug for FragOff {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.len())
    }
}

impl FlagsAndOff {
    pub fn has_flag(&self, flag: FragFlag) -> bool {
        ((self.0 >> 13) as u8 & flag.to_bits()) > 0
    }

    pub fn flags(&self) -> Vec<FragFlag> {
        let mut collected = vec![];

        for flag in FragFlag::iter() {
            if self.has_flag(flag) {
                collected.push(flag);
            }
        }

        collected
    }

    pub fn offset(&self) -> FragOff {
        FragOff(self.0 & 0x1FFF)
    }

    pub fn new_with_offset(offset: FragOff) -> Self {
        Self(offset.0)
    }

    pub fn add_flag(&mut self, flag: FragFlag) {
        self.0 |= (flag.to_bits() as u16) << 13;
    }
}

impl Default for FlagsAndOff {
    fn default() -> Self {
        Self::new_with_offset(FragOff::default())
    }
}

impl Debug for FlagsAndOff {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "(flags={:?}, offset={:?})", self.flags(), self.offset())
    }
}

impl AddAssign<FragFlag> for FlagsAndOff {
    fn add_assign(&mut self, rhs: FragFlag) {
        self.add_flag(rhs);
    }
}

impl TotLen {
    /// Datagram (header + data) length in bytes
    pub fn tot_len(&self) -> usize {
        self.0.to_ne() as usize * 4
    }

    pub fn data_len(&self) -> usize {
        debug_assert_eq!(size_of::<IPv4>(), 20);

        self.tot_len() - size_of::<IPv4>()
    }

    pub fn new_with_tot_len(tot_len: usize) -> Self {
        debug_assert!(tot_len % 4 == 0);
        debug_assert!((tot_len >> 2) <= u16::MAX as usize);

        Self(U16Be::new((tot_len >> 2) as u16))
    }
}

impl Debug for TotLen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.tot_len())
    }
}

impl From<DS> for DSCP {
    fn from(value: DS) -> Self {
        // since enum DSCP has just one non-unit variant, this ub is sound
        // according to pigeonhole principle.
        unsafe { transmute(value.0 as u16) }
    }
}

impl From<DSCP> for ServiceClass {
    fn from(dscp: DSCP) -> Self {
        match dscp {
            DSCP::DF => Self::Standard,
            DSCP::LE => Self::LowerEffort,
            DSCP::EF => Self::Telephony,
            DSCP::VoiceAdmit | DSCP::CS1 | DSCP::CS7 => {
                Self::Undefined(unsafe { transmute::<_, u16>(dscp) as u8 })
            }
            DSCP::AF11 => Self::Highthrouput(DropProb::Low),
            DSCP::AF12 => Self::Highthrouput(DropProb::Medium),
            DSCP::AF13 => Self::Highthrouput(DropProb::High),
            DSCP::AF21 => Self::Lowlatency(DropProb::Low),
            DSCP::AF22 => Self::Lowlatency(DropProb::Medium),
            DSCP::AF23 => Self::Lowlatency(DropProb::High),
            DSCP::AF31 => Self::MultimediaStreaming(DropProb::Low),
            DSCP::AF32 => Self::MultimediaStreaming(DropProb::Medium),
            DSCP::AF33 => Self::MultimediaStreaming(DropProb::High),
            DSCP::AF41 => Self::MultimediaConferencing(DropProb::Low),
            DSCP::AF42 => Self::MultimediaConferencing(DropProb::Medium),
            DSCP::AF43 => Self::MultimediaConferencing(DropProb::High),
            DSCP::CS2 => Self::OAM,
            DSCP::CS3 => Self::BroadcastVideo,
            DSCP::CS4 => Self::RealtimeInteractive,
            DSCP::CS5 => Self::Signaling,
            DSCP::CS6 => Self::NetworkControl,
            DSCP::Undefined(undefined) => Self::Undefined(undefined),
        }
    }
}

impl From<ServiceClass> for DSCP {
    fn from(sc: ServiceClass) -> Self {
        match sc {
            ServiceClass::Lowlatency(drop_prob) => match drop_prob {
                DropProb::Low => Self::AF21,
                DropProb::Medium => Self::AF22,
                DropProb::High => Self::AF23,
            },
            ServiceClass::Highthrouput(drop_prob) => match drop_prob {
                DropProb::Low => Self::AF11,
                DropProb::Medium => Self::AF12,
                DropProb::High => Self::AF13,
            },
            ServiceClass::NetworkControl => Self::CS6,
            ServiceClass::Telephony => Self::EF,
            ServiceClass::Signaling => Self::CS5,
            ServiceClass::MultimediaConferencing(drop_prob) => match drop_prob
            {
                DropProb::Low => Self::AF41,
                DropProb::Medium => Self::AF42,
                DropProb::High => Self::AF43,
            },
            ServiceClass::RealtimeInteractive => Self::CS4,
            ServiceClass::MultimediaStreaming(drop_prob) => match drop_prob {
                DropProb::Low => Self::AF31,
                DropProb::Medium => Self::AF32,
                DropProb::High => Self::AF33,
            },
            ServiceClass::BroadcastVideo => Self::CS3,
            ServiceClass::OAM => Self::CS2,
            ServiceClass::Standard => Self::DF,
            ServiceClass::LowerEffort => Self::LE,
            ServiceClass::Undefined(v) => match v {
                44 => Self::VoiceAdmit,
                8 => Self::CS1,
                56 => Self::CS7,
                undefined => Self::Undefined(undefined),
            },
        }
    }
}

impl Id {
    pub fn new(id: u16) -> Self {
        Self(U16Be::new(id))
    }
}

impl Debug for Id {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.to_ne())
    }
}

impl ToS {
    pub fn ds(&self) -> DSCP {
        DS(self.0 >> 2).into()
    }

    pub fn ecn(&self) -> ECN {
        unsafe { transmute(self.0 & 0x03) }
    }
}

impl From<(DSCP, ECN)> for ToS {
    fn from(value: (DSCP, ECN)) -> Self {
        let (ds, ecn) = value;

        let dscp = ds.to_bits();
        let ecncp = ecn.to_bits();

        Self(dscp << 2 | ecncp)
    }
}

impl Default for ToS {
    fn default() -> Self {
        (DSCP::default(), ECN::default()).into()
    }
}

impl Debug for ToS {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "(ds={:?}, ecn={:?})", DSCP::from(self.ds()), self.ecn())
    }
}

impl Debug for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", ProtocolKind::from(*self))
    }
}

impl IHLAndVer {
    /// number of 32-bit word
    pub fn ihl(&self) -> u8 {
        self.0 & 0x0F
    }

    pub fn ver(&self) -> u8 {
        (self.0 & 0xF0) >> 4
    }

    pub fn with_ihl_and_ver(ihl: u8, ver: u8) -> Self {
        Self(ihl | (ver << 4))
    }

    pub fn with_options_bytes(nbytes: usize) -> Self {
        Self::with_ihl_and_ver(
            ((size_of::<IPv4>() + nbytes) / 4).try_into().unwrap(),
            4,
        )
    }
}

impl Default for IHLAndVer {
    fn default() -> Self {
        Self::with_options_bytes(0)
    }
}

impl Debug for IHLAndVer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "(l={}, v={})", self.ihl(), self.ver())
    }
}
