use std::{io::Write, ops::DerefMut};

use m6ptr::{ByteString, CowBuf, WriteIntoBytes};

use super::*;


////////////////////////////////////////////////////////////////////////////////
//// Macros

// macro_rules! parameters {
//     ($($name:expr => $value:expr),*) => {
//         let mut parameters = ParametersBuf::new();

//         $(
//             parameters = parameters.parameter($name, $value);
//         )*

//         parameters
//     };
// }


////////////////////////////////////////////////////////////////////////////////
//// Structures

pub struct ResponseBuf {
    pub version: Version,
    pub status: StatusCode,
    pub reason: Option<String>,
    pub fields: FieldsBuf,
    pub body: ByteString,
    pub trailers: Option<FieldsBuf>
}

pub struct FieldsBuf {
    pub fields: Vec<FieldBuf>,
}

pub enum FieldBuf {
    ContentType(MediaTypeBuf),
    ContentEncoding(ContentEncoding),
    Server(ServerBuf),
    Date(Date),
    TransferEncoding(TransferEncodingBuf),
    NonStandard(RawFieldBuf),
}

pub struct RawFieldBuf {
    pub name: String,
    pub value: Vec<ByteString>,
}

pub struct MediaTypeBuf {
    pub mime: mime::MediaType,
    pub parameters: ParametersBuf,
}

pub struct ServerBuf {
    pub product: ProductBuf,
    pub rem: Vec<ProductOrCommentBuf>,
}

#[derive(Debug, Clone)]
pub enum ProductOrCommentBuf {
    Product(ProductBuf),
    Comment(ByteString),
}

///
/// ```no_main
/// product = token [ "/" product-version ]
/// product-version = token
/// ```
#[derive(Debug, Clone)]
pub struct ProductBuf {
    pub name: String,
    pub version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParametersBuf {
    value: HashMap<String, ParameterValueBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParameterValueBuf {
    Token(String),
    QStr(ByteString),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferEncodingBuf {
    pub value: Vec<TransferCodingBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferCodingBuf {
    pub coding: parameters::TransferCoding,
    pub parameters: ParametersBuf,
}


////////////////////////////////////////////////////////////////////////////////
//// Implementations

/////////////////////////////////////////
//// implement WrteInToBytes

impl WriteIntoBytes for ResponseBuf {
    fn write_into_bytes<W: Write>(
        &self,
        bytes: &mut W,
    ) -> std::io::Result<()> {
        use FieldBuf::*;

        /* write status line */

        bytes.write_all(self.version.to_string().as_bytes())?;
        bytes.write_all(&[SP as u8])?;
        bytes.write_all(self.status.to_bits().to_string().as_bytes())?;
        bytes.write_all(&[SP as u8])?;

        if let Some(reason) = &self.reason {
            bytes.write_all(reason.as_bytes())?;
        }

        bytes.write_all(b"\n\r")?;

        /* write fields */

        self.fields.write_into_bytes(bytes)?;

        bytes.write_all(b"\n\r")?;

        /* write body */

        // Content-Encoding first

        // body should be compressed when passed

        // and then Transfer-Encoding

        if let Some(te) = self.fields.iter().find_map(|field| {
            if let TransferEncoding(transfer_encoding) = field {
                Some(transfer_encoding)
            }
            else {
                None
            }
        }) {
            use parameters::TransferCoding::*;

            for coding in te.iter() {
                let TransferCodingBuf { coding, .. } = coding;

                match coding {
                    Chunked => todo!(),
                    Compress => todo!(),
                    Deflate => todo!(),
                    Gzip => todo!(),
                    Identity => todo!(),
                    Trailers => todo!(),
                }
            }
        }

        bytes.write_all(&self.body[..])?;

        if let Some(trailers) = &self.trailers {
            trailers.write_into_bytes(bytes)?;
        }

        Ok(())
    }
}

impl WriteIntoBytes for FieldsBuf {
    fn write_into_bytes<W: Write>(
        &self,
        bytes: &mut W,
    ) -> std::io::Result<()> {
        use FieldBuf::*;

        for field in self.fields.iter() {
            field.name().write_into_bytes(bytes)?;
            bytes.write_all(b": ")?;

            match field {
                Server(server) => {
                    server.write_into_bytes(bytes)?;
                }
                _ => unimplemented!(),
            }

            bytes.write_all(b"\n\r")?;
        }

        Ok(())
    }
}

impl WriteIntoBytes for ServerBuf {
    fn write_into_bytes<W: Write>(
        &self,
        bytes: &mut W,
    ) -> std::io::Result<()> {
        self.product.write_into_bytes(bytes)?;

        for prod_or_comment in &self.rem {
            bytes.write_all(&[SP as u8])?;

            match prod_or_comment {
                ProductOrCommentBuf::Product(product) => {
                    product.write_into_bytes(bytes)?;
                }
                ProductOrCommentBuf::Comment(comment) => {
                    bytes.write_all(b"(")?;
                    bytes.write_all(&escape_comment(&comment)[..])?;
                    bytes.write_all(b")")?;
                }
            }
        }

        Ok(())
    }
}

impl WriteIntoBytes for ProductBuf {
    fn write_into_bytes<W: Write>(
        &self,
        bytes: &mut W,
    ) -> std::io::Result<()> {
        bytes.write_all(self.name.as_bytes())?;

        if let Some(ref version) = self.version {
            bytes.write_all(b"/")?;
            bytes.write_all(version.as_bytes())?;
        }

        Ok(())
    }
}

impl ToString for Date {
    fn to_string(&self) -> String {
        self.imf_fixdate()
    }
}

/////////////////////////////////////////
//// implement From references

impl From<Parameters<'_>> for ParametersBuf {
    fn from(value: Parameters) -> Self {
        let mut inner_parameters = HashMap::new();

        for (name, value) in value.value.into_iter() {
            inner_parameters.insert(name.to_string(), value.into());
        }

        Self {
            value: inner_parameters,
        }
    }
}

impl From<ParameterValue<'_>> for ParameterValueBuf {
    fn from(value: ParameterValue<'_>) -> Self {
        match value {
            ParameterValue::Token(value) => Self::Token(value.to_string()),
            ParameterValue::QStr(value) => {
                Self::QStr(value.as_bytestr().to_owned())
            }
        }
    }
}

impl From<MediaType<'_>> for MediaTypeBuf {
    fn from(value: MediaType<'_>) -> Self {
        Self {
            mime: value.mime,
            parameters: value.parameters.into(),
        }
    }
}

impl From<Server<'_>> for ServerBuf {
    fn from(value: Server<'_>) -> Self {
        Self {
            product: value.product.into(),
            rem: value
                .rem
                .into_iter()
                .map(|prod_or_comment| prod_or_comment.into())
                .collect(),
        }
    }
}

impl From<Product<'_>> for ProductBuf {
    fn from(value: Product<'_>) -> Self {
        Self {
            name: value.name.to_string(),
            version: value.version.map(|version| version.to_string()),
        }
    }
}

impl From<ProductOrComment<'_>> for ProductOrCommentBuf {
    fn from(value: ProductOrComment<'_>) -> Self {
        match value {
            ProductOrComment::Product(product) => {
                Self::Product(product.into())
            }
            ProductOrComment::Comment(comment) => {
                Self::Comment(comment.to_vec().into())
            }
        }
    }
}

impl From<Vec<ContentCoding>> for FieldBuf {
    fn from(value: Vec<ContentCoding>) -> Self {
        Self::ContentEncoding(ContentEncoding {
            value: value.into_iter().map(Into::into).collect(),
        })
    }
}

/////////////////////////////////////////
//// implement Deref & DerefMut

impl Deref for FieldsBuf {
    type Target = [FieldBuf];

    fn deref(&self) -> &Self::Target {
        &self.fields
    }
}

impl Deref for TransferEncodingBuf {
    type Target = [TransferCodingBuf];

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl DerefMut for TransferEncodingBuf {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.value
    }
}

/////////////////////////////////////////
//// implement other traits and itself

impl FieldBuf {
    pub fn name(&self) -> FieldName {
        use FieldName::*;

        match self {
            Self::ContentType(..) => ContentType,
            Self::ContentEncoding(..) => ContentEncoding,
            Self::TransferEncoding(..) => TransferEncoding,
            Self::Server(..) => Server,
            Self::Date(..) => Date,
            Self::NonStandard(RawFieldBuf { name, .. }) => {
                NonStandard(name.to_string().into_boxed_str())
            }
        }
    }
}

impl ParametersBuf {
    pub fn new() -> Self {
        Self {
            value: HashMap::new(),
        }
    }

    pub fn parameter(mut self, name: &str, value: ParameterValueBuf) -> Self {
        self.insert(name.to_owned(), value);

        self
    }
}

impl Deref for ParametersBuf {
    type Target = HashMap<String, ParameterValueBuf>;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl DerefMut for ParametersBuf {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.value
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

fn escape_comment<'a>(bytes: &'a ByteStr) -> FlatCow<'a, ByteStr> {
    let mut buf = CowBuf::<ByteStr>::from(bytes);

    for b in bytes.iter().cloned() {
        if b == b'(' || b == b')' || b == b'\\' {
            buf.clone_push(b'\\');
        }

        buf.push(b);
    }

    buf.to_cow()
}
