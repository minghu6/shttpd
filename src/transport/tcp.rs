use std::{
    mem::transmute,
    ops::{Add, AddAssign, Range},
};

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
/// `>= size_of::<TCP>=20, <= 60`
///
/// using high 4 bit
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
    pub window: u16,
    /// Check: pseudo header of IP header + TCP header + TCP data + padding(isn't transmiteed) to make
    /// a multiple of two octets.
    ///
    /// While computing the checksum, the checksum field itself is cleared.
    pub cksum: u16,
    /// Urgent Pointer
    pub urgptr: u16,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct TCPOptsSlice<'a>(&'a [u8]);

pub struct OptUserTimeout(u16);

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
#[derive_to_bits(u8)]
#[repr(u8)]
pub enum MinuteOrSecond {
    Min = 1,
    Sec = 0,
}

#[repr(transparent)]
pub struct OptSACK {
    blocks: Box<[Range<u32>]>,
}

pub struct OptAuth {
    pub keyid: u8,
    pub rnxt_keyid: u8,
    /// Message Authentication Code
    pub mac: Box<[u8]>
}

pub struct OptMPTCP {
    pub subtype: MPTCPSubtype,
    pub data: Box<[u8]>
}

#[repr(u8)]
pub enum MPTCPSubtype {
    /// Multipath Capable
    MPCapable = 0x0,
    /// Join Connection
    MPJoin = 0x1,
    /// Data Sequence Signal (Data ACK and Data Sequence Mapping)
    DSS = 0x2,
    AddAddr = 0x3,
    RemoveAddr = 0x4,
    /// Change Subflow Priority
    MPPrio = 0x5,
    /// Fallback
    MPFail = 0x6,
    MPFastClose = 0x7,
    /// Subflow Reset
    MPTCPRST = 0x8,
    Unassigned(u8),
    /// Reserved for Private Use
    MPExperimental = 0xf
}

pub enum TCPOpt {
    /// kind - 0
    End,
    /// kind - 1
    NOP,
    /// kind - 2, len - 4
    MaxSegSZ {
        mss: u16,
    },
    /// kind - 3, len - 3
    ///
    /// rfc7323
    WindowScale {
        shift: u8,
    },
    /// kind - 8, len - 10
    ///
    /// rfc7323
    ///
    /// Used in the PAWS mechanism protects against errors due to sequence number
    /// wrap-around on high-speed connection. (seq number overflow)
    ///
    /// It's maybe derived from system clock, add variant offset.
    Timestamps {
        tsval: u32,
        tsreply: u32,
    },
    /// kind - 28, len - 4
    ///
    /// rfc 5482
    UserTimeout(OptUserTimeout),
    /// kind - 4, len - 2
    ///
    /// S-ACK permitted
    ///
    /// Selective Ackknowleged (Option) Permitted
    SACKPermitted,
    /// kind - 5, len - 10, 18, 26, 34
    ///
    /// S-ACK
    ///
    /// Selective Ackknowleged (Option)
    ///
    SACK(OptSACK),
    /// kind - 29, len - var >= 4
    ///
    /// obsoletes MD5 authentication (kind = 19)
    ///
    /// TCP AO
    Auth(OptAuth),
    MPTCP(OptMPTCP),
    Unknown {
        kind: u8,
        len: u8,
        data: Box<[u8]>,
    },
}

////////////////////////////////////////////////////////////////////////////////
//// Implementations

impl OptUserTimeout {
    pub fn granularity(&self) -> MinuteOrSecond {
        unsafe { transmute((self.0 >> 15) as u8) }
    }

    pub fn timeout(&self) -> u16 {
        self.0 & 0x7FFF
    }

    pub fn new_with_timeout_granularity(t: u16, g: MinuteOrSecond) -> Self {
        debug_assert!(t & 0x8000 == 0);

        Self((g.to_bits() as u16) << 15 | (t & 0x8000))
    }
}

impl TCPOpt {
    pub fn len(&self) -> usize {
        match self {
            Self::End | Self::NOP => 1,
            Self::MaxSegSZ { .. } => 4,
            Self::WindowScale { .. } => 3,
            Self::Timestamps { .. } => 10,
            Self::UserTimeout(_) => 4,
            Self::SACKPermitted => 2,
            Self::SACK(opt_sack) => opt_sack.blocks.len() * 8,
            Self::Auth(opt_auth) => opt_auth.mac.len() + 4,
            Self::MPTCP(opt_mptcp) => opt_mptcp.data.len() + 2,
            Self::Unknown { data, .. } => data.len(),
        }
    }
}

impl<'a> From<&'a [u8]> for TCPOptsSlice<'a> {
    fn from(value: &'a [u8]) -> Self {
        Self(value)
    }
}

#[cfg(feature = "parse")]
mod parsing {
    use std::{error::Error, fmt::{Debug, Display}};

    use m6parsing::Span;

    use super::*;

    enum ParseTCPOptsErrorReason {
        UncompletedOption {
            expect: u8,
            opt: &'static str,
        },
        WrongLenField {
            opt: &'static str,
            expect: Box<dyn Display>,
            found: u8,
        },
    }

    use ParseTCPOptsErrorReason::*;

    impl Display for ParseTCPOptsErrorReason {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::UncompletedOption { expect, opt } => {
                    write!(f, "Uncompleted {opt} expect {expect} bytes")
                }
                Self::WrongLenField { opt, expect, found } => {
                    write!(
                        f,
                        "Wrong `opt-len` field for [{opt}] expect {expect} found {found} "
                    )
                }
            }
        }
    }

    pub struct ParseTCPOptsError {
        reason: ParseTCPOptsErrorReason,
        span: Span,
    }

    impl Display for ParseTCPOptsError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                f,
                "In TCP Options({}..{}): {}",
                self.span.start, self.span.end, self.reason,
            )
        }
    }

    impl Debug for ParseTCPOptsError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{self}")
        }
    }

    impl Error for ParseTCPOptsError {}

    type Result<T> = std::result::Result<T, ParseTCPOptsError>;

    impl<'a> TCPOptsSlice<'a> {
        pub fn parse(&self) -> Result<Box<[TCPOpt]>> {
            let mut coll = vec![];
            let mut ptr = 0;

            while ptr < self.0.len() {
                let opt = self.parse_one_opt(ptr)?;

                ptr += opt.len();
                coll.push(opt);
            }

            Ok(coll.into_boxed_slice())
        }

        fn parse_one_opt(&self, ptr: usize) -> Result<TCPOpt> {
            debug_assert!(ptr < self.0.len());

            macro_rules! uncomplete_error {
                ($opt:expr, expect=$expect:expr) => {
                    ParseTCPOptsError {
                        reason: UncompletedOption {
                            expect: $expect,
                            opt: $opt,
                        },
                        span: Span {
                            start: ptr,
                            end: self.0.len(),
                        },
                    }
                };
            }

            macro_rules! wrong_len_field {
                ($opt:expr, expect=$expect:expr, found=$found:expr) => {
                    ParseTCPOptsError {
                        reason: WrongLenField {
                            expect: Box::new($expect),
                            found: $found,
                            opt: $opt,
                        },
                        span: Span {
                            start: ptr + 1,
                            end: ptr + 2,
                        },
                    }
                };
            }

            Ok(match self.0[ptr] {
                0 => TCPOpt::End,
                1 => TCPOpt::NOP,
                2 => {
                    let opt_name = "Max Segment Size";
                    let opt_len = 4u8;

                    if self.0.len() < ptr + (opt_len as usize) {
                        Err(uncomplete_error!(opt_name, expect = opt_len))?
                    }

                    if self.0[ptr + 1] != opt_len {
                        Err(wrong_len_field!(
                            opt_name,
                            expect = opt_len,
                            found = self.0[ptr + 1]
                        ))?
                    }

                    TCPOpt::MaxSegSZ {
                        mss: u16::from_be_bytes(
                            self.0[ptr + 2..ptr + (opt_len as usize)]
                                .try_into()
                                .unwrap(),
                        ),
                    }
                }
                3 => {
                    let opt_name = "Window Scale";
                    let opt_len = 3u8;

                    if self.0.len() < ptr + (opt_len as usize) {
                        Err(uncomplete_error!(opt_name, expect = opt_len))?
                    }

                    if self.0[ptr + 1] != (opt_len as _) {
                        Err(wrong_len_field!(
                            opt_name,
                            expect = opt_len,
                            found = self.0[ptr + 1]
                        ))?
                    }

                    TCPOpt::WindowScale {
                        shift: self.0[ptr + 2],
                    }
                }
                4 => {
                    let opt_name = "SACK Permitted";
                    let opt_len = 2u8;

                    if self.0.len() < ptr + (opt_len as usize) {
                        Err(uncomplete_error!(opt_name, expect = opt_len))?
                    }

                    if self.0[ptr + 1] != (opt_len as _) {
                        Err(wrong_len_field!(
                            opt_name,
                            expect = opt_len,
                            found = self.0[ptr + 1]
                        ))?
                    }

                    TCPOpt::SACKPermitted
                }
                5 => {
                    let opt_name = "SACK";
                    let least_opt_len = 10u8;

                    if self.0.len() < ptr + (least_opt_len as usize) {
                        Err(uncomplete_error!(opt_name, expect = least_opt_len))?
                    }

                    let opt_len = self.0[ptr + 1];

                    if self.0[ptr + 1] != (opt_len as _) {
                        Err(wrong_len_field!(
                            opt_name,
                            expect = opt_len,
                            found = self.0[ptr + 1]
                        ))?
                    }

                    if self.0.len() < ptr + (opt_len as usize) {
                        Err(uncomplete_error!(opt_name, expect = opt_len))?
                    }

                    if (opt_len - 2) % 8 != 0 {
                        Err(wrong_len_field!(
                            opt_name,
                            expect = "expect variable length as form of 2 + 8n",
                            found = self.0[ptr + 1]
                        ))?
                    }

                    let mut blocks = Vec::with_capacity((opt_len as usize - 2) / 8);
                    let mut subptr = 0usize;

                    while subptr < opt_len as usize {
                        let lf_edge = u32::from_be_bytes(
                            self.0[ptr+subptr..ptr+subptr+4].try_into().unwrap()
                        );
                        let rh_edge = u32::from_be_bytes(
                            self.0[ptr+subptr+4..ptr+subptr+8].try_into().unwrap()
                        );

                        blocks.push(lf_edge..rh_edge);
                        subptr += 8;
                    }

                    TCPOpt::SACK(OptSACK { blocks: blocks.into_boxed_slice()})
                }
                8 => {
                    let opt_name = "Timestamps";
                    let opt_len = 3u8;

                    if self.0.len() < ptr + (opt_len as usize) {
                        Err(uncomplete_error!(opt_name, expect = opt_len))?
                    }

                    if self.0[ptr + 1] != (opt_len as _) {
                        Err(wrong_len_field!(
                            opt_name,
                            expect = opt_len,
                            found = self.0[ptr + 1]
                        ))?
                    }

                    TCPOpt::Timestamps {
                        tsval: u32::from_be_bytes(
                            self.0[ptr + 2..ptr + 6].try_into().unwrap(),
                        ),
                        tsreply: u32::from_be_bytes(
                            self.0[ptr + 6..ptr + 10].try_into().unwrap(),
                        ),
                    }
                }
                28 => {
                    let opt_name = "User Timeout";
                    let opt_len = 28u8;

                    if self.0.len() < ptr + (opt_len as usize) {
                        Err(uncomplete_error!(opt_name, expect = opt_len))?
                    }

                    if self.0[ptr + 1] != (opt_len as _) {
                        Err(wrong_len_field!(
                            opt_name,
                            expect = opt_len,
                            found = self.0[ptr + 1]
                        ))?
                    }

                    TCPOpt::UserTimeout(OptUserTimeout(u16::from_be_bytes(
                        self.0[ptr + 2..ptr + 4].try_into().unwrap(),
                    )))
                }
                29 => {
                    let opt_name = "AO";
                    let least_opt_len = 4u8;

                    if self.0.len() < ptr + (least_opt_len as usize) {
                        Err(uncomplete_error!(opt_name, expect = least_opt_len))?
                    }

                    let opt_len = self.0[ptr + 1];

                    if opt_len < least_opt_len {
                        Err(wrong_len_field!(
                            opt_name,
                            expect = ">= 4",
                            found = opt_len
                        ))?
                    }

                    if self.0.len() < ptr + (opt_len as usize) {
                        Err(uncomplete_error!(opt_name, expect = opt_len))?
                    }

                    let keyid = self.0[ptr+2];
                    let rnxt_keyid = self.0[ptr+3];
                    let mac = self.0[ptr+4..ptr+(opt_len as usize)].to_vec().into_boxed_slice();

                    TCPOpt::Auth(OptAuth { keyid, rnxt_keyid, mac })
                }
                30 => {
                    let opt_name = "Multiple Path TCP";
                    let least_opt_len = 4u8;

                    if self.0.len() < ptr + (least_opt_len as usize) {
                        Err(uncomplete_error!(opt_name, expect = least_opt_len))?
                    }

                    let opt_len = self.0[ptr + 1];

                    if opt_len < least_opt_len {
                        Err(wrong_len_field!(
                            opt_name,
                            expect = ">= 4",
                            found = opt_len
                        ))?
                    }

                    if self.0.len() < ptr + (opt_len as usize) {
                        Err(uncomplete_error!(opt_name, expect = opt_len))?
                    }

                    let subtype: MPTCPSubtype = unsafe { transmute((self.0[ptr + 2] >> 4) as u16) } ;
                    let data = self.0[ptr+2..ptr+(opt_len as usize)].to_vec().into_boxed_slice();

                    TCPOpt::MPTCP(OptMPTCP { subtype, data })
                }
                _ => {
                    let opt_name = "Unkonwn";
                    let kind = self.0[ptr];
                    let len = self.0[ptr + 1];

                    if ptr + (len as usize) < self.0.len() {
                        Err(uncomplete_error!(opt_name, expect = len as _))?;
                    }

                    let data = self.0[ptr + 2..ptr + (len as usize)].into();

                    TCPOpt::Unknown { kind, len, data }
                }
            })
        }
    }
}

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
    use super::*;

    #[test]
    fn test_flag_arithmetic() {
        let flags = TCPFlag::Ack + TCPFlag::Cwr + TCPFlag::Fin;

        assert!(flags.has_flag(TCPFlag::Ack));
        assert!(flags.has_flag(TCPFlag::Cwr));
        assert!(flags.has_flag(TCPFlag::Fin));
        assert!(!flags.has_flag(TCPFlag::Rst));
    }

    #[test]
    fn test_mod_encapsulation() {}
}
