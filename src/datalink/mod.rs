use std::mem::transmute;

use m6tobytes::*;

pub mod arp;

////////////////////////////////////////////////////////////////////////////////
//// Structures

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, FromBytes, ToBytes)]
#[repr(transparent)]
pub struct Mac([u8; 6]);

/// network-layer Protocol
///
/// Assigned based from https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[derive_to_bits_into(EthType)]
#[derive_to_bits(u16)]
#[repr(u16)]
#[non_exhaustive]
pub enum EthTypeSpec {
    IPv4 = 0x0800,
    ARP = 0x0806,
    IPv6 = 0x86DD,
    // repr(u16) for u32 storage
    Oth(u16)
}

#[derive(Clone, Copy, Eq, PartialEq, Hash, FromBytes, ToBytes)]
#[derive_to_bits(u16)]
#[repr(transparent)]
pub struct EthType(u16);

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[derive_to_bits_into(EthProto)]
#[derive_to_bits(u16)]
#[repr(u16)]
pub enum EthProtoSpec {
    Len(u16),
    Undefined(u16),
    EthType(EthType)
}

///
/// + `>= 1536 (0x0600)` EthType (Ethernet-V2)
///
/// + `> 1500, < 1536` undefined
///
/// + `<= 1500 (0x05cc)` Payload Length (new IEEE 802.3)
///
#[derive(Clone, Copy, Eq, PartialEq, Hash, FromBytes, ToBytes)]
#[derive_to_bits(u16)]
#[repr(transparent)]
pub struct EthProto(u16);

/// Ethernet-V2 aka DIX Ethernet frame and IEEE 802.3 frame (header)
///
/// payload: 64-1500 bytes (exclude header)
///
/// 64 bytes: 512-bit slot time used for collision detection in the Ethernet LAN architecture.
///
#[derive(Clone, Copy, PartialEq, Eq, Hash, FromBytes, ToBytes)]
#[repr(packed)]
#[repr(C)]
pub struct Eth {
    pub dst: Mac,
    pub src: Mac,
    pub proto: EthProto
}

////////////////////////////////////////////////////////////////////////////////
//// Implementations

impl From<EthProto> for EthProtoSpec {
    fn from(value: EthProto) -> Self {
        let v = value.to_bits();

        match v {
            // 1501
            ..0x05dd => Self::Len(v),
            0x05dd..0x0600 => Self::Undefined(v),
            0x0600.. => Self::EthType(EthType(v))
        }
    }
}

impl From<EthType> for EthTypeSpec {
    fn from(value: EthType) -> Self {
        let v = value.to_bits();

        match v {
            0x0800 | 0x0806 | 0x86DD => unsafe { transmute(v as u32) },
            _ => Self::Oth(v)
        }
    }
}
