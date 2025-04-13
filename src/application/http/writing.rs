use std::{
    ascii::Char::*,
    io::Write,
};

use m6io::{CowBuf, WriteIntoBytes};

use super::*;


////////////////////////////////////////////////////////////////////////////////
//// Macros

////////////////////////////////////////////////////////////////////////////////
//// Constants

const CRLF: &[u8; 2] = b"\r\n";

////////////////////////////////////////////////////////////////////////////////
//// Structures


////////////////////////////////////////////////////////////////////////////////
//// Implementations

/////////////////////////////////////////
//// implement WrteInToBytes

impl WriteIntoBytes for Response {
    fn write_into_bytes<W: Write>(&self, w: &mut W) -> std::io::Result<usize> {
        let mut n = 0;

        /* write status line */

        n += self.version.to_string().write_into_bytes(w)?;
        n += Space.as_str().write_into_bytes(w)?;

        n += self.status.to_bits().to_string().write_into_bytes(w)?;
        n += Space.as_str().write_into_bytes(w)?;

        if let Some(reason) = &self.reason {
            n += reason.write_into_bytes(w)?;
        }

        n += CRLF.write_into_bytes(w)?;

        /* write fields */

        n += self.fields.write_into_bytes(w)?;

        n += CRLF.write_into_bytes(w)?;

        Ok(n)
    }
}

impl WriteIntoBytes for Fields {
    fn write_into_bytes<W: Write>(&self, w: &mut W) -> std::io::Result<usize> {
        use Field::*;

        let mut n = 0;

        for field in self.fields.iter() {
            n += field.name().to_string().write_into_bytes(w)?;
            n += Colon.to_string().write_into_bytes(w)?;
            n += Space.to_string().write_into_bytes(w)?;

            n += match field {
                Server(server) => server.write_into_bytes(w),
                Accept(accept) => accept.write_into_bytes(w),
                Connection(connection) => connection.write_into_bytes(w),
                ContentType(media_type) => media_type.write_into_bytes(w),
                ContentEncoding(content_encoding) => {
                    content_encoding.write_into_bytes(w)
                }
                ContentLength(content_length) => {
                    content_length.to_string().write_into_bytes(w)
                }
                Date(date) => date.to_string().write_into_bytes(w),
                Host(host) => host.to_string().write_into_bytes(w),
                TransferEncoding(transfer_encoding) => {
                    transfer_encoding.write_into_bytes(w)
                }
                NonStandard(raw_field) => raw_field.write_into_bytes(w),
            }?;

            n += CRLF.write_into_bytes(w)?;
        }

        Ok(n)
    }
}

impl WriteIntoBytes for RawField {
    fn write_into_bytes<W: Write>(&self, w: &mut W) -> std::io::Result<usize> {
        let mut n = 0;

        for (i, member) in self.value.iter().enumerate() {
            if i != 0 {
                n += Comma.to_string().write_into_bytes(w)?;
            }

            n += member.write_into_bytes(w)?;
        }

        Ok(n)
    }
}

impl WriteIntoBytes for TransferEncoding {
    fn write_into_bytes<W: Write>(&self, w: &mut W) -> std::io::Result<usize> {
        let mut n = 0;

        for (i, coding) in self.iter().enumerate() {
            if i != 0 {
                Comma.to_string().write_into_bytes(w)?;
            }

            n += coding.write_into_bytes(w)?;
        }

        Ok(n)
    }
}

impl WriteIntoBytes for TransferCoding {
    fn write_into_bytes<W: Write>(&self, w: &mut W) -> std::io::Result<usize> {
        let mut n = 0;

        n += self.coding.to_string().write_into_bytes(w)?;
        n += self.parameters.write_into_bytes(w)?;

        Ok(n)
    }
}

impl WriteIntoBytes for ContentEncoding {
    fn write_into_bytes<W: Write>(&self, w: &mut W) -> std::io::Result<usize> {
        let mut n = 0;

        for (i, coding) in self.iter().enumerate() {
            if i != 0 {
                n += Comma.to_string().write_into_bytes(w)?;
            }

            n += coding.to_string().write_into_bytes(w)?;
        }

        Ok(n)
    }
}

impl WriteIntoBytes for MediaType {
    fn write_into_bytes<W: Write>(&self, w: &mut W) -> std::io::Result<usize> {
        let mut n = 0;

        n += self.mime.to_string().write_into_bytes(w)?;
        n += self.parameters.write_into_bytes(w)?;

        Ok(n)
    }
}

impl WriteIntoBytes for Connection {
    fn write_into_bytes<W: Write>(&self, w: &mut W) -> std::io::Result<usize> {
        let mut n = 0;

        for opt in self.iter() {
            n += opt.write_into_bytes(w)?;
        }

        Ok(n)
    }
}

impl WriteIntoBytes for ConnectionOption {
    fn write_into_bytes<W: Write>(&self, w: &mut W) -> std::io::Result<usize> {
        self.to_string().write_into_bytes(w)
    }
}

impl WriteIntoBytes for Server {
    fn write_into_bytes<W: Write>(&self, w: &mut W) -> std::io::Result<usize> {
        let mut n = self.product.write_into_bytes(w)?;

        for prod_or_comment in &self.rem {
            n += Space.as_str().write_into_bytes(w)?;

            match prod_or_comment {
                ProductOrComment::Product(product) => {
                    n += product.write_into_bytes(w)?;
                }
                ProductOrComment::Comment(comment) => {
                    n += b"(".write_into_bytes(w)?;
                    n += comment.write_into_bytes(w)?;
                    n += b")".write_into_bytes(w)?;
                }
            }
        }

        Ok(n)
    }
}

impl WriteIntoBytes for Product {
    fn write_into_bytes<W: Write>(&self, w: &mut W) -> std::io::Result<usize> {
        let mut n = self.name.write_into_bytes(w)?;

        if let Some(ref version) = self.version {
            n += Solidus.to_string().write_into_bytes(w)?;
            n += version.write_into_bytes(w)?;
        }

        Ok(n)
    }
}

impl WriteIntoBytes for Accept {
    fn write_into_bytes<W: Write>(&self, w: &mut W) -> std::io::Result<usize> {
        let mut n = 0;

        for (i, (media_range, q)) in self.iter().enumerate() {
            if i != 0 {
                n += Comma.to_string().write_into_bytes(w)?;
            }

            n += media_range.write_into_bytes(w)?;
            n += format!(";q={q}").write_into_bytes(w)?;
        }

        Ok(n)
    }
}

impl WriteIntoBytes for MediaRange {
    fn write_into_bytes<W: Write>(&self, w: &mut W) -> std::io::Result<usize> {
        let mut n = 0;

        n += self.mime.to_string().write_into_bytes(w)?;
        n += self.parameters.write_into_bytes(w)?;

        Ok(n)
    }
}

impl WriteIntoBytes for Parameters {
    fn write_into_bytes<W: Write>(&self, w: &mut W) -> std::io::Result<usize> {
        let mut n = 0;

        for pair in self.iter() {
            n += Semicolon.to_string().write_into_bytes(w)?;
            n += pair.write_into_bytes(w)?;
        }

        Ok(n)
    }
}

impl WriteIntoBytes for Pair {
    fn write_into_bytes<W: Write>(&self, w: &mut W) -> std::io::Result<usize> {
        let mut n = 0;

        n += self.name.write_into_bytes(w)?;
        n += EqualsSign.as_str().write_into_bytes(w)?;
        n += self.value.write_into_bytes(w)?;

        Ok(n)
    }
}

impl WriteIntoBytes for PairValue {
    fn write_into_bytes<W: Write>(&self, w: &mut W) -> std::io::Result<usize> {
        Ok(match self {
            PairValue::Token(token) => token.write_into_bytes(w)?,
            PairValue::QStr(byte_string) => {
                let mut n = QuotationMark.as_str().write_into_bytes(w)?;
                let bstr = byte_string.as_bstr();

                n += escape_qdstr(&bstr.into())
                    .write_into_bytes(w)?;
                n += QuotationMark.as_str().write_into_bytes(w)?;
                n
            }
        })
    }
}

impl ToString for Date {
    fn to_string(&self) -> String {
        self.imf_fixdate()
    }
}

impl ToString for Host {
    fn to_string(&self) -> String {
        format!(
            "{}{}",
            self.host,
            self.port.map(|port| format!(":{port}")).unwrap_or_default()
        )
    }
}


/////////////////////////////////////////
//// implement From references


/////////////////////////////////////////
//// implement Deref & DerefMut

/////////////////////////////////////////
//// implement other traits and itself


////////////////////////////////////////////////////////////////////////////////
//// Functions

fn escape_qdstr<'a>(bytes: &FlatCow<'a, ByteStr>) -> FlatCow<'a, ByteStr> {
    let mut buf = CowBuf::<ByteStr>::from(bytes);

    for b in bytes.iter().cloned() {
        if b == b'"' || b == b'\\' {
            buf.clone_push(b'\\');
        }

        buf.push(b);
    }

    buf.to_cow()
}

// fn escape_comment<'a>(bytes: &'a ByteStr) -> FlatCow<'a, ByteStr> {
//     let mut buf = CowBuf::<ByteStr>::from(bytes);

//     for b in bytes.iter().cloned() {
//         if b == b'(' || b == b')' || b == b'\\' {
//             buf.clone_push(b'\\');
//         }

//         buf.push(b);
//     }

//     buf.to_cow()
// }
