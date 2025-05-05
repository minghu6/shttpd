use std::{ascii::Char::*, io::Write};

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

        for field in self.values.iter() {
            n += field.name().to_string().write_into_bytes(w)?;
            n += Colon.to_string().write_into_bytes(w)?;
            n += Space.to_string().write_into_bytes(w)?;

            n += match field {
                Server(server) => server.write_into_bytes(w),
                UserAgent(user_agent) => user_agent.write_into_bytes(w),
                Allow(allow) => allow.write_into_bytes(w),
                Accept(accept) => accept.write_into_bytes(w),
                AcceptEncoding(accept_encoding) => {
                    accept_encoding.write_into_bytes(w)
                }
                Connection(connection) => connection.write_into_bytes(w),
                ContentType(media_type) => media_type.write_into_bytes(w),
                ContentEncoding(content_encoding) => {
                    content_encoding.write_into_bytes(w)
                }
                ContentLength(content_length) => {
                    content_length.to_string().write_into_bytes(w)
                }
                Date(date) => date.to_string().write_into_bytes(w),
                ETag(etag) => etag.write_into_bytes(w),
                IfMatch(ifmatch) | IfNoneMatch(ifmatch) => {
                    ifmatch.write_into_bytes(w)
                }
                IfModifiedSince(date) | IfUnmodifiedSince(date) => {
                    date.imf_fixdate().write_into_bytes(w)
                }
                IfRange(ifrange) => ifrange.write_into_bytes(w),
                Host(host) => host.to_string().write_into_bytes(w),
                Range(range_spec) => range_spec.write_into_bytes(w),
                ContentRange(content_range)  => content_range.write_into_bytes(w),
                AcceptRanges(accept_ranges) => accept_ranges.write_into_bytes(w),
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

impl WriteIntoBytes for ChunkedBody {
    fn write_into_bytes<W: Write>(&self, w: &mut W) -> std::io::Result<usize> {
        let mut n = 0;

        for chunk in self.chunks.iter() {
            n += chunk.write_into_bytes(w)?;
        }

        n += self.last_chunk.write_into_bytes(w)?;

        n += self.trailer_section.write_into_bytes(w)?;
        n += CRLF.write_into_bytes(w)?;

        Ok(n)
    }
}

impl WriteIntoBytes for Chunk {
    fn write_into_bytes<W: Write>(&self, w: &mut W) -> std::io::Result<usize> {
        let mut n = 0;

        n += format!("{:x}", self.size).write_into_bytes(w)?;
        n += self.ext.write_into_bytes(w)?;
        n += CRLF.write_into_bytes(w)?;

        if self.size > 0 {
            n += self.data.write_into_bytes(w)?;
            n += CRLF.write_into_bytes(w)?;
        }

        Ok(n)
    }
}

impl WriteIntoBytes for ChunkExt {
    fn write_into_bytes<W: Write>(&self, w: &mut W) -> std::io::Result<usize> {
        let mut n = 0;

        for ChunkExtUnit { name, value } in self.iter() {
            n += Semicolon.as_str().write_into_bytes(w)?;
            n += name.to_string().write_into_bytes(w)?;

            if let Some(param) = value {
                n += EqualsSign.as_str().write_into_bytes(w)?;
                n += param.write_into_bytes(w)?;
            }
        }

        Ok(n)
    }
}

impl WriteIntoBytes for EntityTag {
    fn write_into_bytes<W: Write>(&self, w: &mut W) -> std::io::Result<usize> {
        let mut n = 0;

        if self.is_weak {
            n += "W/".write_into_bytes(w)?;
        }

        n += QuotationMark.as_str().write_into_bytes(w)?;
        n += self.opaque_tag.write_into_bytes(w)?;
        n += QuotationMark.as_str().write_into_bytes(w)?;

        Ok(n)
    }
}

impl WriteIntoBytes for IfMatch {
    fn write_into_bytes<W: Write>(&self, w: &mut W) -> std::io::Result<usize> {
        let mut n = 0;

        match self {
            IfMatch::Star => n += '*'.to_string().write_into_bytes(w)?,
            IfMatch::List(entity_tags) => {
                for (i, etag) in entity_tags.iter().enumerate() {
                    if i != 0 {
                        n += Comma.to_string().write_into_bytes(w)?;
                        n += Space.to_string().write_into_bytes(w)?;
                    }

                    n += etag.write_into_bytes(w)?;
                }
            }
        }

        Ok(n)
    }
}

impl WriteIntoBytes for IfRange {
    fn write_into_bytes<W: Write>(&self, w: &mut W) -> std::io::Result<usize> {
        let mut n = 0;

        n += match self {
            IfRange::Tag(entity_tag) => entity_tag.write_into_bytes(w),
            IfRange::Date(date) => date.imf_fixdate().write_into_bytes(w),
        }?;

        Ok(n)
    }
}

impl WriteIntoBytes for RangesSpecifier {
    fn write_into_bytes<W: Write>(&self, w: &mut W) -> std::io::Result<usize> {
        let mut n = 0;

        n += self.unit.to_string().write_into_bytes(w)?;
        n += EqualsSign.to_string().write_into_bytes(w)?;

        for (i, range_sepc) in self.set.iter().enumerate() {
            if i != 0 {
                n += Comma.to_string().write_into_bytes(w)?;
                n += Space.to_string().write_into_bytes(w)?;
            }

            n += range_sepc.write_into_bytes(w)?;
        }

        Ok(n)
    }
}

impl WriteIntoBytes for RangeSpec {
    fn write_into_bytes<W: Write>(&self, w: &mut W) -> std::io::Result<usize> {
        let mut n = 0;

        match self {
            RangeSpec::IntRange { start, end } => {
                n += format!("{start}-").write_into_bytes(w)?;

                if let Some(end) = end {
                    n += end.to_string().write_into_bytes(w)?;
                }
            }
            RangeSpec::SuffixRange { end } => {
                n += format!("-{end}").write_into_bytes(w)?;
            }
            RangeSpec::OtherRange(byte_string) => n += byte_string.write_into_bytes(w)?,
        }

        Ok(n)
    }
}

impl WriteIntoBytes for AcceptRanges {
    fn write_into_bytes<W: Write>(&self, w: &mut W) -> std::io::Result<usize> {
        let mut n = 0;

        for (i, range_unit) in self.iter().enumerate() {
            if i != 0 {
                n += Comma.to_string().write_into_bytes(w)?;
                n += Space.to_string().write_into_bytes(w)?;
            }

            n += range_unit.to_string().write_into_bytes(w)?;
        }

        Ok(n)
    }
}

impl WriteIntoBytes for ContentRange {
    fn write_into_bytes<W: Write>(&self, w: &mut W) -> std::io::Result<usize> {
        let mut n = 0;

        n += self.unit.to_string().write_into_bytes(w)?;
        n += Space.to_string().write_into_bytes(w)?;

        match &self.range_or_unsatisfied {
            RangeOrUnsatisfied::Range(range_resp) => {
                n += range_resp.write_into_bytes(w)?;
            },
            RangeOrUnsatisfied::Unsatisfied(len) => n += format!("*/{len}").write_into_bytes(w)?,
        }

        Ok(n)
    }
}

impl WriteIntoBytes for RangeResp {
    fn write_into_bytes<W: Write>(&self, w: &mut W) -> std::io::Result<usize> {
        let mut n = 0;

        n += format!("{}-{}", self.range.start(), self.range.end()).write_into_bytes(w)?;
        n += Solidus.to_string().write_into_bytes(w)?;

        if let Some(len) = self.complete_length {
            n += len.to_string().write_into_bytes(w)?;
        }
        else {
            n += Asterisk.to_string().write_into_bytes(w)?;
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

impl WriteIntoBytes for UserAgent {
    fn write_into_bytes<W: Write>(&self, w: &mut W) -> std::io::Result<usize> {
        Server::from(self.clone()).write_into_bytes(w)
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

impl WriteIntoBytes for Allow {
    fn write_into_bytes<W: Write>(&self, w: &mut W) -> std::io::Result<usize> {
        let mut n = 0;

        for (i, method) in self.iter().enumerate() {
            if i != 0 {
                n += Comma.to_string().write_into_bytes(w)?;
                n += Space.to_string().write_into_bytes(w)?;
            }

            n += method.to_string().write_into_bytes(w)?;
        }

        Ok(n)
    }
}

impl WriteIntoBytes for Accept {
    fn write_into_bytes<W: Write>(&self, w: &mut W) -> std::io::Result<usize> {
        let mut n = 0;

        for (i, (media_range, opt_q)) in self.iter().enumerate() {
            if i != 0 {
                n += Comma.to_string().write_into_bytes(w)?;
            }

            n += media_range.write_into_bytes(w)?;

            if let Some(q) = opt_q {
                n += format!(";q={q}").write_into_bytes(w)?;
            }
        }

        Ok(n)
    }
}

impl WriteIntoBytes for AcceptEncoding {
    fn write_into_bytes<W: Write>(&self, w: &mut W) -> std::io::Result<usize> {
        let mut n = 0;

        for (i, (codings, opt_q)) in self.iter().enumerate() {
            if i != 0 {
                n += Comma.to_string().write_into_bytes(w)?;
            }

            n += codings.write_into_bytes(w)?;

            if let Some(q) = opt_q {
                n += format!(";q={q}").write_into_bytes(w)?;
            }
        }

        Ok(n)
    }
}

impl WriteIntoBytes for Codings {
    fn write_into_bytes<W: Write>(&self, w: &mut W) -> std::io::Result<usize> {
        use Codings::*;

        match self {
            Spec(content_coding) => content_coding
                .to_string()
                .to_ascii_lowercase()
                .write_into_bytes(w),
            Identity => "identity".write_into_bytes(w),
            Star => "*".write_into_bytes(w),
        }
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

impl WriteIntoBytes for Parameter {
    fn write_into_bytes<W: Write>(&self, w: &mut W) -> std::io::Result<usize> {
        let mut n = 0;

        n += self.name.write_into_bytes(w)?;
        n += EqualsSign.as_str().write_into_bytes(w)?;
        n += self.value.write_into_bytes(w)?;

        Ok(n)
    }
}

impl WriteIntoBytes for ParameterValue {
    fn write_into_bytes<W: Write>(&self, w: &mut W) -> std::io::Result<usize> {
        Ok(match self {
            ParameterValue::Token(token) => token.write_into_bytes(w)?,
            ParameterValue::QStr(byte_string) => {
                let mut n = QuotationMark.as_str().write_into_bytes(w)?;
                let bstr = byte_string.as_bstr();

                n += escape_qdstr(&bstr.into()).write_into_bytes(w)?;
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

// fn write_into_list_based_field_value<W: Write, T: WriteIntoBytes>(
//     w: &mut W,
//     list: &[T],
// ) -> std::io::Result<usize> {
//     let mut n = 0;

//     for (i, t) in list.iter().enumerate() {
//         if i != 0 {
//             n += Comma.to_string().write_into_bytes(w)?;
//         }

//         n += t.write_into_bytes(w)?;
//     }

//     Ok(n)
// }

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
