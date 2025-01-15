use m6tobytes::*;

#[derive(Clone, Copy, PartialEq, Eq, Hash, FromBytes, ToBytes)]
#[repr(packed)]
#[repr(C)]
pub struct UDP {
    pub src: u16,
    pub dst: u16,
    /// lenghth of udp datagram bytes
    pub len: u16,
    /// UDP checksum computation is optional for IPv4. If a checksum is not used
    /// it should be set to the value zero.
    ///
    /// Check: pseudo IP header + UDP header + UDP data + padding zero to make a multiple of two octets.
    ///
    /// While computing the checksum, the checksum field itself is cleared.
    pub cksum: u16
}
