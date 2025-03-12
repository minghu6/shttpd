use m6ptr::CowBuf;

use super::*;


////////////////////////////////////////////////////////////////////////////////
//// Traits

pub(crate) trait WriteInToBytes {
    fn write_into_bytes(&self, bytes: &mut Vec<u8>);
}


////////////////////////////////////////////////////////////////////////////////
//// Implementations

impl<'a> Response<'a> {

    pub fn write_into_bytes(&self, bytes: &mut Vec<u8>) {
        use Field::*;

        /* write status line */

        bytes.extend(self.version.to_string().as_bytes());
        bytes.push(SP as u8);
        bytes.extend(self.status.to_bits().to_string().as_bytes());
        bytes.push(SP as u8);

        if let Some(reason) = &self.reason {
            bytes.extend(reason.as_bytes());
        }

        bytes.extend(b"\n\r");

        /* write fields */

        for field in self.fields.iter() {
            field.name().write_into_bytes(bytes);
            bytes.extend(b": ");

            match field {
                Server(server) => {
                    server.write_into_bytes(bytes);
                },
                _ => unimplemented!()
            }

            bytes.extend(b"\n\r");
        }

        /* write body */

        bytes.extend(b"\n\r");
        bytes.extend(&self.body[..])
    }
}

impl WriteInToBytes for FieldName {
    fn write_into_bytes(&self, bytes: &mut Vec<u8>) {
        bytes.extend(self.to_string().as_bytes());
    }
}

impl<'a> WriteInToBytes for Server<'a> {
    fn write_into_bytes(&self, bytes: &mut Vec<u8>) {
        self.product.write_into_bytes(bytes);

        for prod_or_comment in &self.rem {
            bytes.push(SP as u8);

            match prod_or_comment {
                ProductOrComment::Product(product) => {
                    product.write_into_bytes(bytes);
                },
                ProductOrComment::Comment(comment) => {
                    bytes.push(b'(');
                    bytes.extend(&escape_comment(&comment)[..]);
                    bytes.push(b')');
                },
            }
        }
    }
}

impl<'a> WriteInToBytes for Product<'a> {
    fn write_into_bytes(&self, bytes: &mut Vec<u8>) {
        bytes.extend(self.name.as_bytes());

        if let Some(ref version) = self.version {
            bytes.push(b'/');
            bytes.extend(version.as_bytes());
        }
    }
}

impl<'a> WriteInToBytes for Date {
    fn write_into_bytes(&self, bytes: &mut Vec<u8>) {
        bytes.extend(self.imf_fixdate().as_bytes());
    }
}

////////////////////////////////////////////////////////////////////////////////
//// Functions

#[allow(unused)]
fn escape_qdstr<'a>(bytes: &FlatCow<'a, [u8]>) -> FlatCow<'a, [u8]> {
    let mut buf = CowBuf::<[u8]>::from(bytes);

    for b in bytes.iter().cloned() {
        if b == b'"' || b == b'\\' {
            buf.clone_push(b'\\');
        }

        buf.push(b);
    }

    buf.to_cow()
}

fn escape_comment<'a>(bytes: &FlatCow<'a, ByteStr>) -> FlatCow<'a, ByteStr> {
    let mut buf = CowBuf::<ByteStr>::from(bytes);

    for b in bytes.iter().cloned() {
        if b == b'(' || b == b')' || b == b'\\' {
            buf.clone_push(b'\\');
        }

        buf.push(b);
    }

    buf.to_cow()
}
