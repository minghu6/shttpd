use std::mem::transmute;

use m6tobytes::*;


////////////////////////////////////////////////////////////////////////////////
//// Structures

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[derive_to_bits_into(ICMPType)]
#[derive_to_bits(u8)]
#[non_exhaustive]
#[repr(u8)]
pub enum ICMPTypeSpec {
    EchoReply = 0,
    DestinationUnreachable = 3,
    RedirectMessage = 5,
    EchoRequest = 8,
    /// [Router Advertisement](https://en.wikipedia.org/wiki/ICMP_Router_Discovery_Protocol)
    RouterAdvertisement = 9,
    RouterSolicitation = 10,
    TimeExceeded = 11,
    /// Bad IP header
    BadParam = 12,
    Timestamp = 13,
    TimestampReply = 14,
    ExtendedEchoRequest = 42,
    ExtendedEchoReply = 43,
    Oth(u8)
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, FromBytes, ToBytes)]
#[derive_to_bits(u8)]
#[repr(transparent)]
pub struct ICMPType(u8);

#[derive(Clone, Copy, PartialEq, Eq, Hash, FromBytes, ToBytes)]
#[derive_to_bits(u8)]
#[repr(transparent)]
pub struct ICMPCode(u8);

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[derive_to_bits_into(ICMPCode)]
#[derive_to_bits(u8)]
#[repr(u8)]
pub enum UnreachCode {
    DstNetworkUnreachable = 0,
    DstHostUnreachable = 1,
    DstProtocolUnreachable = 2,
    DstPortUnreachable = 3,
    FragRequiredDFFlagset = 4,
    SrcRouteFailed = 5,
    DstNetworkUnknown = 6,
    DstHostUnknown = 7,
    SrcHostIsolated = 8,
    NetworkAdmiProhibited = 9,
    HostAdmiProhibited = 10,
    NetworkUnreachableforToS = 11,
    HostUnreachableforToS = 12,
    /// 13 Communication Administratively Prohibited
    CommunicationAdmiProhibited = 13,
    HostPrecedenceViolation = 14,
    /// 15 Sent by a router when receiving a datagram whose Precedence value (priority)
    /// is lower than the minimum allowed for the network at that time.
    PrecedenceCutOff = 15,
    Oth(u8)
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[derive_to_bits_into(ICMPCode)]
#[derive_to_bits(u8)]
#[repr(u8)]
pub enum RedirectCode {
    ForNetwork = 0,
    ForHost = 1,
    ForToSAndNetwork = 2,
    ForToSAndHost = 3,
    Oth(u8)
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[derive_to_bits_into(ICMPCode)]
#[derive_to_bits(u8)]
#[repr(u8)]
pub enum TimeExceededCode {
    TTLExpired = 0,
    FragmentReassemblyTimeExceeded = 1,
    Oth(u8)
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[derive_to_bits_into(ICMPCode)]
#[derive_to_bits(u8)]
#[repr(u8)]
pub enum BadIPHeaderCode {
    PtrIndicatesError = 0,
    MissingRequiredOption = 1,
    BadLen = 2,
    Oth(u8)
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[derive_to_bits_into(ICMPCode)]
#[derive_to_bits(u8)]
#[repr(u8)]
pub enum ExtendedErrorCode {
    NoError = 0,
    MalformedQuery = 1,
    NoSuchInterface = 2,
    NoSuchTableEntry = 3,
    MultipleInterfacesSatisfyQuery = 4,
    Oth(u8)
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, FromBytes, ToBytes)]
pub struct ICMP {
    pub ty: ICMPType,
    pub code: ICMPCode,
    pub cksum: u16,
    pub un: u32
}

////////////////////////////////////////////////////////////////////////////////
//// Implementations

impl From<ICMPCode> for UnreachCode {
    fn from(value: ICMPCode) -> Self {
        let v = value.to_bits();

        match v {
            ..=15 => unsafe { transmute(v as u16) },
            _ => Self::Oth(v)
        }
    }
}

impl From<ICMPCode> for RedirectCode {
    fn from(value: ICMPCode) -> Self {
        let v = value.to_bits();

        match v {
            ..=3 => unsafe { transmute(v as u16) },
            _ => Self::Oth(v)
        }
    }
}

impl From<ICMPCode> for TimeExceededCode {
    fn from(value: ICMPCode) -> Self {
        let v = value.to_bits();

        match v {
            0 | 1 => unsafe { transmute(v as u16) },
            _ => Self::Oth(v)
        }
    }
}

impl From<ICMPCode> for BadIPHeaderCode {
    fn from(value: ICMPCode) -> Self {
        let v = value.to_bits();

        match v {
            ..=2 => unsafe { transmute(v as u16) },
            _ => Self::Oth(v)
        }
    }
}

impl From<ICMPCode> for ExtendedErrorCode {
    fn from(value: ICMPCode) -> Self {
        let v = value.to_bits();

        match v {
            ..=4 => unsafe { transmute(v as u16) },
            _ => Self::Oth(v)
        }
    }
}

impl From<ICMPType> for ICMPTypeSpec {
    fn from(value: ICMPType) -> Self {
        let v = value.to_bits();

        match v {
            0..=3 => {
                unsafe { transmute(v as u16) }
            }
            _ => Self::Oth(v)
        }
    }
}


#[cfg(test)]
mod tests {

}
