use std::mem::transmute;

use m6tobytes::*;

use crate::{
    datalink::{EthType, Mac},
    network::IPv4Addr,
};


////////////////////////////////////////////////////////////////////////////////
//// Structures

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[derive_to_bits_into(HType)]
#[derive_to_bits(u16)]
#[repr(u16)]
pub enum HTypeSpec {
    Ethernet10Mb = 1,
    ExptEher3Mb = 2,
    AmateurRadioAX25 = 3,
    PPTokenRing = 4,
    Chaos = 5,
    IEEE802 = 6,
    ARCNET = 7,
    Hyperchannel = 8,
    Lanstar = 9,
    AutonetShortAddr = 10,
    LocalTalk = 11,
    /// IBM PCNet or SYTEX LocalNet
    LocalNet = 12,
    Ultralink = 13,
    SMDS = 14,
    FrameReply = 15,
    /// Asynchronous Transmission Mode
    ATM16 = 16,
    HDLC = 17,
    FibreChannel = 18,
    ATM19 = 19,
    SerialLine = 20,
    ATM21 = 21,
    MilStd188_220 = 22,
    Metricom = 23,
    IEEE1394_1995 = 24,
    MAPOS = 25,
    Twinaxial = 26,
    EUI64 = 27,
    HIPARP = 28,
    IPARPISO78163 = 29,
    ARPSec = 30,
    IPSecTunnel = 31,
    InfiniBand = 32,
    TIA102ProjInf = 33,
    WiegandInf = 34,
    PureIP = 35,
    HWEXP1 = 36,
    HFI = 37,
    UnifiedBus = 38,
    HwExp2 = 256,
    AEth = 257,
    /// 39-255, 258-65534 Unassigned
    Unassigned(u16),
    ///
    /// 0 | 0xFF Reserved
    Reserved(u16)
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, ToBytes, FromBytes)]
#[derive_to_bits(u16)]
#[repr(transparent)]
pub struct HType(u16);

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[derive_to_bits_into(ARPOp)]
#[derive_to_bits(u16)]
#[repr(u16)]
#[non_exhaustive]
pub enum ARPOpSpec {
    Request = 1,
    Reply = 2,
    Oth(u16)
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, FromBytes, ToBytes)]
#[derive_to_bits(u16)]
#[repr(transparent)]
pub struct ARPOp(u16);

#[derive(Clone, Copy, PartialEq, Eq, Hash, FromBytes, ToBytes)]
#[repr(packed)]
#[repr(C)]
pub struct ARP {
    pub htype: HType,
    /// Protocol Type
    pub ptype: EthType,
    /// Hardware (Address) Length
    ///
    /// Ethernet =6
    pub hlen: u8,
    /// Protocol (Address) Length
    ///
    /// IPv4 =4
    pub plen: u8,
    /// Operation
    pub oper: ARPOp,
    /// Sender Hardware Address
    pub sha: Mac,
    /// Sender Protocol Address
    pub spa: IPv4Addr,
    /// Target hardware address
    pub tha: Mac,
    /// Target protocol address
    pub tpa: IPv4Addr,
}


////////////////////////////////////////////////////////////////////////////////
//// Implementations

impl From<ARPOp> for ARPOpSpec {
    fn from(value: ARPOp) -> Self {
        let v= value.to_bits();

        match v {
            1 | 2 => unsafe { transmute(v as u32) },
            _ => Self::Oth(v),
        }
    }
}

impl From<HType> for HTypeSpec {
    fn from(value: HType) -> Self {
        let v = value.to_bits();

        match v {
            39..=255 | 258..=0xFFFE => Self::Unassigned(v),
            0 | 0xFFFF => Self::Reserved(v),
            _ => unsafe { transmute(v as u32) },
        }
    }
}
