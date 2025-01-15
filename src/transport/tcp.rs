use std::ops::{Add, AddAssign};

use m6tobytes::*;


////////////////////////////////////////////////////////////////////////////////
//// Structures

#[derive(Clone, Copy, PartialEq, Eq, Hash, FromBytes, ToBytes)]
#[derive_to_bits(u8)]
#[repr(transparent)]
pub struct Flags(u8);

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[derive_to_bits(u8)]
#[repr(u8)]
pub enum TCPFlag {
    /// Finished flag
    Fin = 0b0000_0001,
    /// Synchronisation flag (connection request)
    Syn = 0b0000_0010,
    /// Reset flag
    Rst = 0b0000_0100,
    /// Push flag, go ahead and send
    ///
    Psh = 0b0000_1000,
    /// Acknowledgment flag
    Ack = 0b0001_0000,
    /// Urgent flag
    Urg = 0b0010_0000,
    /// Explicit Congestion Notification Capable flag
    Ece = 0b0100_0000,
    /// Congestion window reduced flag
    Cwr = 0b1000_0000,
}

/// Data offset (from TCP header to TCP data) with unit of 4 bytes.
///
/// 4 bit
#[derive(Clone, Copy, PartialEq, Eq, Hash, FromBytes, ToBytes)]
#[derive_to_bits(u8)]
#[repr(transparent)]
pub struct DOff(u8);

#[derive(Clone, Copy, PartialEq, Eq, Hash, FromBytes, ToBytes)]
#[repr(packed)]
#[repr(C)]
pub struct TCP {
    pub src: u16,
    pub dst: u16,
    pub seq: u32,
    /// When ACK is set,
    /// this field is the next sequence number expected by ACK sender.
    pub ack_seq: u32,
    pub doff: DOff,
    pub flags: Flags,
    /// window numbers of unit
    ///
    /// see also [Window scaling](https://en.wikipedia.org/wiki/Transmission_Control_Protocol#Window_scaling)
    window: u16,
    /// Check: pseudo header of IP header + TCP header + TCP data + padding(isn't transmiteed) to make
    /// a multiple of two octets.
    ///
    /// While computing the checksum, the checksum field itself is cleared.
    cksum: u16,
    /// Urgent Pointer
    urgptr: u16
}


////////////////////////////////////////////////////////////////////////////////
//// Implementations

impl Add for TCPFlag {
    type Output = Flags;

    fn add(self, rhs: Self) -> Self::Output {
        Flags(self.to_bits() | rhs.to_bits())
    }
}

impl Flags {
    pub fn has_flag(&self, flag: TCPFlag) -> bool {
        self.0 & flag.to_bits() > 0
    }

    pub fn add_flag(&mut self, flag: TCPFlag) {
        self.0 |= flag.to_bits()
    }
}

impl Add<TCPFlag> for Flags {
    type Output = Self;

    fn add(self, rhs: TCPFlag) -> Self::Output {
        Self(self.0 + rhs.to_bits())
    }
}

impl AddAssign<TCPFlag> for Flags {
    fn add_assign(&mut self, rhs: TCPFlag) {
        self.add_flag(rhs);
    }
}

impl DOff {
    pub fn hdr_len(&self) -> usize {
        (self.0 >> 4) as usize * 4
    }

    pub fn opt_len(&self) -> usize {
        self.hdr_len() - size_of::<TCP>()
    }

    pub fn new_with_hdr_len(hdr_len: usize) -> Self {
        debug_assert!(hdr_len % 4 == 0);
        debug_assert!(hdr_len / 4 <= 0xF);

        Self(((hdr_len / 4) as u8) << 4)
    }
}


#[cfg(test)]
mod tests {
    use super::TCPFlag;

    #[test]
    fn test_flag_arithmetic() {
        let flags = TCPFlag::Ack + TCPFlag::Cwr + TCPFlag::Fin;

        assert!(flags.has_flag(TCPFlag::Ack));
        assert!(flags.has_flag(TCPFlag::Cwr));
        assert!(flags.has_flag(TCPFlag::Fin));
        assert!(!flags.has_flag(TCPFlag::Rst));
    }
}
