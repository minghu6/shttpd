use std::{ffi::c_char, fmt::{Debug, Display}, mem::transmute};

use derive_more::derive::{Deref, DerefMut};
use m6tobytes::*;

use crate::be::U16Be;

pub mod arp;

////////////////////////////////////////////////////////////////////////////////
//// Structures

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, FromBytes, ToBytes)]
#[repr(transparent)]
pub struct Mac([u8; 6]);

/// network-layer Protocol
///
/// Assigned based from https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[derive_to_bits(u16)]
#[repr(u16)]
#[non_exhaustive]
pub enum EthTypeKind {
    IPv4 = 0x0800,
    ARP = 0x0806,
    IPv6 = 0x86DD,
    // repr(u16) for u32 storage
    Oth(u16)
}

#[derive(Default, Clone, Copy, Eq, PartialEq, Hash, Deref, DerefMut)]
#[repr(transparent)]
pub struct EthType(U16Be);

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum EthProtoKind {
    Len(u16),
    Undefined(u16),
    EthType(EthTypeKind)
}

///
/// + `>= 1536 (0x0600)` EthType (Ethernet-V2)
///
/// + `> 1500, < 1536` undefined
///
/// + `<= 1500 (0x05cc)` Payload Length (new IEEE 802.3)
///
#[derive(Clone, Copy, Eq, PartialEq, Hash, Deref, DerefMut)]
#[repr(transparent)]
pub struct EthProto(U16Be);

/// Ethernet-V2 aka DIX Ethernet frame and IEEE 802.3 frame (header)
///
/// payload: 64-1500 bytes (exclude header)
///
/// 64 bytes: 512-bit slot time used for collision detection in the Ethernet LAN architecture.
///
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[repr(packed)]
#[repr(C)]
pub struct Eth {
    pub dst: Mac,
    pub src: Mac,
    pub proto: EthProto
}

////////////////////////////////////////////////////////////////////////////////
//// Implementations

impl Eth {
    /// Max Frame Lenght (14 + 1500)
    pub const FRAME_LEN: usize = 1514;
    /// Min Frame Lenght (14 + 46)
    pub const ZLEN: usize = 60;
}

impl Mac {
    pub const BROADCAST: Self = Self([0xFF; 6]);
    pub const ZERO: Self = unsafe { std::mem::zeroed() };

    pub fn from_bytes(src: &[u8]) -> Self {
        let mut arr = [0; 6];

        arr.copy_from_slice(&src[..6]);

        Self(arr)
    }

    pub fn into_arr8(self) -> [u8; 8] {
        let mut arr8 = [0u8; 8];

        arr8[..6].copy_from_slice(&self.0);

        arr8
    }
}

impl Default for Mac {
    fn default() -> Self {
        Self::ZERO
    }
}

impl<const N: usize> From<[c_char; N]> for Mac {
    fn from(value: [c_char; N]) -> Self {
        assert!(N >= 6, "lenght expect >= 6, found {N}");

        Self::from_bytes(&value.map(|c| c as u8))
    }
}

impl Display for Mac {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, c) in self.0.iter().enumerate() {
            if i > 0 {
                write!(f, ":")?;
            }

            write!(f, "{c:02x}")?;
        }

        Ok(())
    }
}

impl EthProto {
    pub(crate) fn new(value: u16) -> Self {
        Self(U16Be::new(value))
    }

    pub fn into_kind(self) -> EthProtoKind {
        EthProtoKind::from(self)
    }
}

impl Debug for EthProto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.into_kind())
    }
}

impl From<EthType> for EthProto {
    fn from(value: EthType) -> Self {
        Self(value.0)
    }
}

impl From<EthProtoKind> for EthProto {
    fn from(value: EthProtoKind) -> Self {
        EthProto::new(value.to_bits())
    }
}

impl EthProtoKind {
    pub fn to_bits(&self) -> u16 {
        use EthProtoKind::*;

        match *self {
            Len(len) => len,
            Undefined(undef) => undef,
            EthType(eth_type_spec) => eth_type_spec.to_bits(),
        }
    }
}

impl From<EthTypeKind> for EthProtoKind {
    fn from(value: EthTypeKind) -> Self {
        Self::EthType(value)
    }
}

impl From<EthProto> for EthProtoKind {
    fn from(value: EthProto) -> Self {
        let v = value.to_ne();

        match v {
            // 1501
            ..0x05dd => Self::Len(v),
            0x05dd..0x0600 => Self::Undefined(v),
            0x0600.. => Self::EthType(EthTypeKind::from(v))
        }
    }
}

impl EthType {
    /// host order value
    pub unsafe fn new_unchecked(value: u16) -> Self {
        Self(U16Be::new(value))
    }

    pub fn to_kind(&self) -> EthTypeKind {
        (*self).into()
    }
}

impl Debug for EthType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.to_kind())
    }
}

impl EthTypeKind {
    pub fn from_bits(bits: u16) -> Self {
        Self::from(bits)
    }
}

impl Into<EthType> for EthTypeKind {
    fn into(self) -> EthType {
        unsafe { EthType::new_unchecked(self.to_bits()) }
    }
}

impl From<EthType> for EthTypeKind {
    fn from(value: EthType) -> Self {
        EthTypeKind::from_bits(value.to_ne())
    }
}

impl From<u16> for EthTypeKind {
    fn from(value: u16) -> Self {
        match value {
            0x0800 | 0x0806 | 0x86DD => unsafe { transmute(value as u32) },
            _ => Self::Oth(value)
        }
    }
}

impl Into<EthProto> for EthTypeKind {
    fn into(self) -> EthProto {
        EthProtoKind::EthType(self.into()).into()
    }
}
