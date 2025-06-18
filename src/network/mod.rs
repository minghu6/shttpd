use std::{
    fmt::{Debug, Display},
    net::Ipv4Addr,
};

use m6tobytes::*;

use crate::be::U16Be;

pub mod icmp;
pub mod ip;


////////////////////////////////////////////////////////////////////////////////
//// Structures

#[derive(Default, Clone, Copy, PartialEq, Eq, Hash, FromBytes, ToBytes)]
#[repr(transparent)]
pub struct IPv4Addr([u8; 4]);

#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(transparent)]
pub struct InetCkSum(U16Be);

////////////////////////////////////////////////////////////////////////////////
//// Implementations

impl InetCkSum {
    /// from normal u16
    pub const fn new(t: u16) -> Self {
        Self(U16Be::new(t))
    }

    pub const fn from_be(t: u16) -> Self {
        Self(U16Be::from_be(t))
    }

    pub const fn to_bits(&self) -> u16 {
        self.0.to_ne()
    }

    pub const fn is_zero(&self) -> bool {
        self.to_bits() == 0
    }
}

impl From<u16> for InetCkSum {
    fn from(value: u16) -> Self {
        Self::new(value)
    }
}

impl Debug for InetCkSum {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:x}", self.0.to_ne())
    }
}

impl Display for InetCkSum {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl IPv4Addr {
    pub const fn from_bytes(bytes: [u8; 4]) -> Self {
        Self(bytes)
    }

    pub const fn octets(&self) -> [u8; 4] {
        self.0
    }

    ///
    /// ```
    /// let bytes = [0x12, 0x34, 0x56, 0x78];
    /// let u32 = u32::from_be_bytes(bytes);
    /// assert_eq!(u32, 0x12345678);
    ///
    /// ```
    ///
    pub const fn to_bits(&self) -> u32 {
        u32::from_be_bytes(self.0)
    }

    /// from be u32
    pub const fn from_bits(value: u32) -> Self {
        Self(value.to_ne_bytes())
    }

    pub const fn to_std_ipv4(&self) -> Ipv4Addr {
        Ipv4Addr::from_octets(self.0)
    }

    pub const fn is_loopback(&self) -> bool {
        self.to_std_ipv4().is_loopback()
    }
}

impl Display for IPv4Addr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl Debug for IPv4Addr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ipv4: Ipv4Addr = (*self).into();

        write!(f, "{ipv4}")
    }
}

///
/// ```
/// use osimodel::network::IPv4Addr;
/// use std::net::Ipv4Addr;
///
/// let ip = IPv4Addr::from_bytes([127, 0, 0, 1]);
/// assert_eq!(ip, Into::<IPv4Addr>::into(Ipv4Addr::new(127, 0, 0, 1)));
/// ```
///
impl From<Ipv4Addr> for IPv4Addr {
    fn from(value: Ipv4Addr) -> Self {
        Self(value.to_bits().to_be_bytes())
    }
}

impl Into<Ipv4Addr> for IPv4Addr {
    fn into(self) -> Ipv4Addr {
        Ipv4Addr::from_octets(self.0)
    }
}

////////////////////////////////////////////////////////////////////////////////
//// Functions

/// Based from [rfc1071](https://www.rfc-editor.org/rfc/inline-errata/rfc1071.html)
///
/// To check a checksum, the 1's complement sum is computed over the
/// same set of octets, including the checksum field.  If the result
/// is all 1 bits (-0 in 1's complement arithmetic), the check
/// succeeds.
pub fn inet_cksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = data.chunks_exact(2);

    for chunk in chunks.by_ref() {
        sum =
            sum.wrapping_add(u16::from_be_bytes([chunk[0], chunk[1]]) as u32);
    }

    if let [last_byte] = chunks.remainder() {
        sum = sum.wrapping_add(u16::from_be_bytes([*last_byte, 0]) as u32);
    }

    /* fold 32-bit into 16-bit */

    while sum >> 16 > 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // as form of one's completion
    !(sum as u16)
}


#[cfg(test)]
mod tests {

    use super::*;
    use crate::network::{icmp::{ICMPCode, ICMPTypeKind, ICMP}};

    #[test]
    fn test_inet_cksum() {
        // basic test
        let test1 = [0, 0, 0, 0];
        assert_eq!(inet_cksum(&test1), 0xFFFF);

        let recv1 = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xb8,
            0x61, 0xc0, 0xa8, 00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];

        // let iphdr = from_raw_slice::<IPv4>(&recv1);
        // println!("iphdr: {iphdr:#?}");

        let recv1_v = !inet_cksum(&recv1);
        assert_eq!(recv1_v, 0xFFFF);

        let icmp = ICMP {
            ty: ICMPTypeKind::EchoRequest.into(),
            code: ICMPCode::default(),
            cksum: InetCkSum::default(),
            un: 1234,
        }
        .checksummed();

        let icmp_recv_cksum = inet_cksum(as_raw_slice(&icmp));

        assert!(!icmp_recv_cksum == 0xFFFF);
        assert!(!inet_cksum(as_raw_slice(&icmp)) == 0xFFFF);
        assert!(icmp.verify_cksum());

        // assert!(icmp.verify_cksum(), "should be {}", icmp.checksummed().cksum);

        // ip header
        let test3 = [
            0x45, 0x00, 0x00, 0x30, 0x80, 0x4C, 0x40, 0x00, 0x80, 0x06, 0x00,
            0x00, 0xD3, 0x43, 0x11, 0x7B, 0xCB, 0x51, 0x15, 0x3D,
        ];
        assert_eq!(inet_cksum(&test3), 0xB52E);
    }
}
