use std::mem::transmute;

use derive_more::derive::{Deref, DerefMut};
use m6tobytes::*;

use crate::{
    be::U16Be, datalink::{EthType, Mac}, network::IPv4Addr
};


////////////////////////////////////////////////////////////////////////////////
//// Structures

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[derive_to_bits(u16)]
#[repr(u16)]
pub enum HTypeKind {
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

#[derive(Clone, Copy, PartialEq, Eq, Hash, Deref, DerefMut)]
#[repr(transparent)]
pub struct HType(U16Be);

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[derive_to_bits(u16)]
#[repr(u16)]
#[non_exhaustive]


pub enum ARPOpKind {
    Request = 1,
    Reply = 2,
    Oth(u16)
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Deref, DerefMut)]
#[repr(transparent)]
pub struct ARPOp(U16Be);

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
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
    pub op: ARPOp,
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

impl ARPOp {
    pub fn new(value: u16) -> Self {
        Self(U16Be::new(value))
    }

    /// copy to avoid read unaligned on reference
    pub fn to_kind(self) -> ARPOpKind {
        (self).into()
    }
}

impl From<ARPOpKind> for ARPOp {
    fn from(value: ARPOpKind) -> Self {
        ARPOp::new(value.to_bits())
    }
}

impl std::fmt::Debug for ARPOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if f.alternate() {
            write!(f, "{:#?}", ARPOpKind::from(*self))
        }
        else {
            write!(f, "{:?}", ARPOpKind::from(*self))
        }
    }
}

impl From<ARPOp> for ARPOpKind {
    fn from(value: ARPOp) -> Self {
        let v = value.to_ne();

        match v {
            1 | 2 => unsafe { transmute(v as u32) },
            _ => Self::Oth(v),
        }
    }
}

impl HType {
    pub fn to_kind(&self) -> HTypeKind {
        (*self).into()
    }
}

impl std::fmt::Debug for HType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.to_kind())
    }
}

impl From<HType> for HTypeKind {
    fn from(value: HType) -> Self {
        let v = value.to_ne();

        match v {
            39..=255 | 258..=0xFFFE => Self::Unassigned(v),
            0 | 0xFFFF => Self::Reserved(v),
            _ => unsafe { transmute(v as u32) },
        }
    }
}

impl From<HTypeKind> for HType {
    fn from(value: HTypeKind) -> Self {
        HType(U16Be::new(value.to_bits()))
    }
}
