use m6tobytes::*;

pub mod icmp;
pub mod ip;


#[derive(Clone, Copy, PartialEq, Eq, Hash, FromBytes, ToBytes)]
#[repr(transparent)]
pub struct IPv4Addr([u8; 4]);

/// Based from [rfc1071](https://www.rfc-editor.org/rfc/inline-errata/rfc1071.html)
///
/// To check a checksum, the 1's complement sum is computed over the
/// same set of octets, including the checksum field.  If the result
/// is all 1 bits (-0 in 1's complement arithmetic), the check
/// succeeds.
pub fn inet_cksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;

    for chunk in data.chunks(2) {
        if chunk.len() == 2 {
            sum += u16::from_ne_bytes(chunk.try_into().unwrap()) as u32;
        }
        else {
            sum += chunk[0] as u32;
        }
    }

    /* fold 32-bit into 16-bit */

    while sum >> 16 > 0 {
        sum = sum & 0xFFF + sum >> 16;
    }

    // as form of one's completion
    !(sum as u16)
}

