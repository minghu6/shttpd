use std::{
    fmt::{Debug, Display}, mem::transmute, num::ParseIntError, ops::RangeInclusive, string::ToString
};

pub use case_insensitive_string::CaseInsensitiveString;
use chrono::{
    DateTime, Datelike, NaiveDate, NaiveDateTime, NaiveTime, TimeZone,
    Timelike, Weekday,
};
use derive_more::derive::{Deref, DerefMut};
pub use m6io::FlatCow;
use m6io::{ByteStr, ByteString};
use m6tobytes::{derive_from_bits, derive_to_bits};
use nonempty::NonEmpty;
use parameters::ContentCoding;
use strum::{Display, EnumIter, EnumString, IntoStaticStr};
use uri::RequestTarget;

use super::{charset, mime};

pub mod parsing;
pub mod uri;
pub mod writing;

////////////////////////////////////////////////////////////////////////////////
//// Constants


////////////////////////////////////////////////////////////////////////////////
//// Structures

#[derive(Debug)]
pub enum Message {
    Request(Request),
    Response(Response),
}

#[derive(Debug)]
pub struct Request {
    pub method: Method,
    pub target: RequestTarget,
    pub version: Version,
    pub fields: Fields,
}

#[derive(Debug)]
pub struct Response {
    pub version: Version,
    pub status: StatusCode,
    pub reason: Option<String>,
    pub fields: Fields,
}

#[derive(Debug)]
pub struct CompleteRequest {
    pub request: Request,
    pub body: Body,
}

#[derive(Debug)]
pub struct CompleteResponse {
    pub response: Response,
    pub body: Body,
}

#[derive()]
pub enum Body {
    Empty,
    Complete(Box<[u8]>),
    Chunked,
}

#[derive(Debug)]
pub enum StartLine {
    RequestLine(RequestLine),
    StatusLine(StatusLine),
}

#[derive(Debug)]
pub struct RequestLine {
    method: Method,
    target: RequestTarget,
    version: Version,
}

#[derive(Debug, PartialEq, Eq)]
pub struct StatusLine {
    pub version: Version,
    pub status: StatusCode,
    pub reason: Option<String>,
}

/// case-sensitive
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, EnumString, Display)]
#[strum(serialize_all = "UPPERCASE")]
pub enum Method {
    Options,
    Get,
    Post,
    Put,
    Delete,
    Head,
    Trace,
    Connect,
    Patch,
}

/// case-sensitive
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    EnumString,
    Display,
)]
#[non_exhaustive]
pub enum Version {
    #[strum(serialize = "HTTP/0.9")]
    HTTP09,
    #[strum(serialize = "HTTP/1.0")]
    HTTP10,
    #[strum(serialize = "HTTP/1.1")]
    HTTP11,
    #[strum(serialize = "HTTP/2")]
    H2,
    #[strum(serialize = "HTTP/3")]
    H3,
}

/// Refer [RFC-9110#status-codes]
/// (https://datatracker.ietf.org/doc/html/rfc9110#name-status-codes)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[derive_to_bits(u16)]
#[repr(u16)]
pub enum StatusCode {
    /// response to client test if the request (maybe large)
    /// could pass to server.
    Continue = 100,
    SwitchingProtocols = 101,

    Ok = 200,
    Created = 201,
    Accepted = 202,
    NonAuthoriativeInfo = 203,
    /// success response witout extra content
    NonContent = 204,
    /// reset content view like refresh
    ResetContent = 205,
    PartialContent = 206,

    MultipleChoices = 300,
    MovePermanently = 301,
    Found = 302,
    SeeOther = 303,
    NotModified = 304,
    /// Deprecated use proxy
    Deprecated305 = 305,
    Deprecated306 = 306,
    TemporaryRedirect = 307,
    PermanentRedirect = 308,

    BadRequest = 400,
    Unauthoriozed = 401,
    PaymentRequired = 402,
    Forbidden = 403,
    NotFound = 404,
    MethodNotAllowed = 405,
    /// there is no acceptable resource for user agent
    ///
    /// it should contains a list of available representation
    NotAcceptable = 406,
    ProxyAuthenticationRequired = 407,
    RequestTimeout = 408,
    /// this code is used in situations where the user might be able to
    /// resolve the conflict and resubmit the request.
    /// the server should generate content that includes enough information
    /// for a user to recognize the source of the conflic
    Conflict = 409,
    /// resource is no longer available permanently,
    /// if no facilities to know if it's permanent it should use 404/
    Gone = 410,
    /// require `Content-Lenght` field
    LengthRequired = 411,
    PreconditionFailed = 412,
    ContentTooLarge = 413,
    URITooLong = 414,
    UnsupportedMediaType = 415,
    RangeNotSatisfiable = 416,
    /// require `Expect` field
    ExpectationFailed = 417,
    April1Unused = 418,
    MisdirectedRequest = 421,
    /// content syntax is ok, but instructions is erroneous (semantics error)
    UnprocessableContent = 422,
    UpgradeRequired = 426,

    InternalServerError = 500,
    NotImplemented = 501,
    BadGateway = 502,
    ServiceUnavailable = 503,
    GatewayTimeout = 504,
    HTTPVersionNotSupported = 505,
}

#[derive(Debug, Deref, DerefMut)]
pub struct Fields {
    pub values: Vec<Field>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Display, EnumIter, IntoStaticStr)]
#[strum(
    ascii_case_insensitive,
    parse_err_fn = to_infalliable,
    parse_err_ty = Infallible,
    serialize_all = "Train-Case"
)]
pub enum FieldName {
    Allow,
    Accept,
    AcceptEncoding,
    Connection,
    ContentType,
    ContentEncoding,
    ContentLength,
    Date,
    #[strum(serialize = "ETag")]
    ETag,
    IfMatch,
    IfNoneMatch,
    IfModifiedSince,
    IfUnmodifiedSince,
    IfRange,
    Host,
    Server,
    TransferEncoding,
    Range,
    AcceptRanges,
    ContentRange,
    UserAgent,
    #[strum(default)]
    NonStandard(CaseInsensitiveString),
}

#[derive(Debug)]
pub enum Field {
    Allow(Allow),
    Accept(Accept),
    AcceptEncoding(AcceptEncoding),
    Connection(Connection),
    ContentType(MediaType),
    ContentEncoding(ContentEncoding),
    ContentLength(u64),
    Date(Date),
    ETag(EntityTag),
    Host(Host),
    IfMatch(IfMatch),
    IfNoneMatch(IfMatch),
    IfModifiedSince(HTTPDate),
    IfUnmodifiedSince(HTTPDate),
    IfRange(IfRange),
    Server(Server),
    Range(RangesSpecifier),
    AcceptRanges(AcceptRanges),
    ContentRange(ContentRange),
    UserAgent(UserAgent),
    TransferEncoding(TransferEncoding),
    NonStandard(RawField),
}

/// derive trait `Ord` based on
/// [lexicographic order]
/// (https://doc.rust-lang.org/std/cmp/trait.Ord.html#derivable)
/// which is name here.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RawField {
    pub name: String,
    pub value: Vec<ByteString>,
}

///
/// ```abnf
/// Host = uri-host [ ":" port ]
/// ```
///
#[derive(Debug)]
pub struct Host {
    pub host: String,
    pub port: Option<u16>,
}

///
/// xx=yy ; mm=nn ...
///
/// ```abnf
/// parameters      = *( OWS ";" OWS [ parameter ] )
/// parameter       = parameter-name "=" parameter-value
/// parameter-name  = token
/// parameter-value = ( token / quoted-string )
/// ```
#[derive(Debug, Deref, DerefMut, Clone)]
pub struct Parameters {
    value: Vec<Parameter>,
}

#[derive(Debug, Clone)]
pub struct Parameter {
    pub name: String,
    pub value: ParameterValue,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ParameterValue {
    Token(String),
    QStr(ByteString),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SingletonFieldValue {
    Token(String),
    QStr(ByteString),
    Oth(ByteString),
}

///
/// Field `MediaType`
///
#[derive(Debug, Clone)]
pub struct MediaType {
    pub mime: mime::MediaType,
    pub parameters: Parameters,
}

#[derive(Debug)]
pub struct MediaRange {
    pub mime: mime::MediaRangeType,
    pub parameters: Parameters,
}

#[derive(Debug, Deref, DerefMut)]
pub struct Allow {
    pub values: Vec<Method>,
}

///
/// [Accept](https://datatracker.ietf.org/doc/html/rfc9110#name-accept)
///
/// Senders using weights SHOULD send "q" last (after all media-range parameters).
/// Recipients SHOULD process any parameter named "q" as weight,
/// regardless of parameter ordering.
///
/// Note: Use of the "q" parameter name to control content negotiation would interfere with
/// any media type parameter having the same name. Hence,
/// the media type registry disallows parameters named "q".
///
#[derive(Debug, Deref, DerefMut)]
pub struct Accept {
    pub values: Vec<(MediaRange, Option<f32>)>,
}

/// deprecated field (for utf-8 has become nearly ubiquitous)
pub struct AcceptCharset {
    pub values: Vec<(Charset, Option<f32>)>,
}

///
/// Empty Encoding = `Identity`
///
/// ```abnf
/// Accept-Encoding = #( codings [ weight ] )
/// ```
///
#[derive(Debug, Deref, DerefMut)]
pub struct AcceptEncoding {
    pub values: Vec<(Codings, Option<f32>)>,
}


///
/// ```abnf
/// codings = content-coding / "identity" / "*"
/// ```
///
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codings {
    Spec(ContentCoding),
    Identity,
    Star,
}

#[derive(Debug, Clone)]
pub enum Charset {
    Spec(charset::Charset),
    Star,
}

pub type ContentType = MediaType;

pub struct ContentLength {
    pub value: u64,
}

#[derive(Debug, Deref, DerefMut)]
pub struct ContentEncoding {
    pub value: Vec<ContentCoding>,
}

#[derive(Debug, Deref, DerefMut)]
pub struct Connection {
    pub value: Vec<ConnectionOption>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, EnumString, Display)]
#[strum(ascii_case_insensitive)]
pub enum ConnectionOption {
    Close,
    TE,
    Upgrade,
    #[strum(serialize = "Keep-Alive")]
    KeepAlive,
    Oth(String),
}

///
///
/// ```ABNF
/// #transfer-coding  ; >= 1
/// ```
///
#[derive(Debug, Deref, DerefMut)]
pub struct TransferEncoding {
    pub value: Vec<TransferCoding>,
}

///
/// ```abnf
/// transfer-coding    = token *( OWS ";" OWS transfer-parameter )
/// transfer-parameter = token BWS "=" BWS ( token / quoted-string )
/// ```
///
#[derive(Debug)]
pub struct TransferCoding {
    pub coding: parameters::TransferCoding,
    pub parameters: Parameters,
}

pub mod parameters {
    use strum::{Display, EnumString};

    ///
    /// According to [IANA Hypertext Transfer Protocol (HTTP) Parameters
    /// ](https://www.iana.org/assignments/http-parameters/http-parameters.xhtml)
    ///
    #[derive(Debug, Clone, Copy, PartialEq, Eq, EnumString, Display)]
    #[strum(ascii_case_insensitive, serialize_all = "snake_case")]
    pub enum ContentCoding {
        /// AES-GCM encryption with a 128-bit content encryption key
        AES128GCM,
        /// Brotli Compressed Data Format
        Br,
        /// UNIX "compress" data format
        Compress,
        /// "Dictionary-Compressed Brotli" data format
        DCB,
        /// "Dictionary-Compressed Zstandard" data format
        DCZ,
        /// "deflate" compressed data ([RFC1951]) inside the "zlib" data format
        Deflate,
        /// W3C Efficient XML Interchange
        EXI,
        Gzip,
        // /// reserved "no encoding", identity(x) = x
        // Identity,
        /// Network Transfer Format for Java Archives
        #[strum(serialize = "pack200-gzip")]
        Pack200GZip,
        /// A stream of bytes compressed using the Zstandard protocol
        /// with a Window_Size of not more than 8 MB.
        Zstd,
    }

    ///
    /// According to [IANA Hypertext Transfer Protocol (HTTP) Parameters
    /// ](https://www.iana.org/assignments/http-parameters/http-parameters.xhtml)
    ///
    #[derive(Debug, Clone, Copy, PartialEq, Eq, EnumString, Display)]
    #[strum(ascii_case_insensitive)]
    pub enum TransferCoding {
        /// Transfer in a series of chunks
        Chunked,
        /// UNIX "compress" data format
        Compress,
        Deflate,
        Gzip,
        Identity,
        /// reserved
        Trailers,
    }
}

///
/// ```abnf
/// chunked-body = *chunk
///                last-chunk
///                trailer-section
///                CRLF
/// ```
///
#[derive(Debug)]
pub struct ChunkedBody {
    pub chunks: Vec<Chunk>,
    pub last_chunk: Chunk,
    pub trailer_section: Fields,
}

///
/// ```abnf
/// chunk          = chunk-size [ chunk-ext ] CRLF
///                  chunk-data CRLF
/// chunk-size     = 1*HEXDIG
/// last-chunk     = 1*("0") [ chunk-ext ] CRLF
/// chunk-data     = 1*OCTET ; a sequence of chunk-size octets
/// ```
///
#[derive(Debug)]
pub struct Chunk {
    pub size: u32,
    pub ext: ChunkExt,
    pub data: ByteString,
}

/// without CRLF
#[derive(Debug)]
pub struct ChunkHeader {
    pub size: u32,
    pub ext: ChunkExt,
}

///
/// ```abnf
///  chunk-ext = *( BWS ";" BWS chunk-ext-name
///                 [ BWS "=" BWS chunk-ext-val ] )
/// ```
///
#[derive(Debug, Deref, DerefMut)]
pub struct ChunkExt {
    value: Vec<ChunkExtUnit>,
}

#[derive(Debug)]
pub struct ChunkExtUnit {
    pub name: String,
    pub value: Option<ParameterValue>,
}

///
/// [HTTP-date](https://datatracker.ietf.org/doc/html/rfc9110#name-date-time-formats)
///
/// HTTP-date = IMF-fixdate / obs-date
///
/// An example of the preferred format is
///
/// `Sun, 06 Nov 1994 08:49:37 GMT    ; IMF-fixdate`
///
/// Examples of the two obsolete formats are
///
/// `Sunday, 06-Nov-94 08:49:37 GMT   ; obsolete RFC 850 format`
///
/// `Sun Nov  6 08:49:37 1994         ; ANSI C's asctime() format`
///
///
/// `chrono::TimeZone::with_ymd_and_hms`
///
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Date {
    pub day_name: DayName,
    pub month: MonthName,
    pub day: Day,
    pub year: Year,
    pub time_of_day: TimeOfDay,
}

pub type HTTPDate = Date;

#[derive(Clone, Copy, PartialEq, Eq, Hash, EnumString, Debug, Display)]
#[derive_from_bits(u8)]
#[repr(u8)]
pub enum DayName {
    Mon = 1,
    Tue,
    Wed,
    Thu,
    Fri,
    Sat,
    Sun,
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone)]
/// ```abnf
/// entity-tag = [ weak ] opaque-tag
/// weak       = %s"W/"
/// ```
pub struct EntityTag {
    pub is_weak: bool,
    pub opaque_tag: ByteString,
}

/////////////////////////////
//// Preconditions

#[derive(Clone, Debug, PartialEq, Eq)]
///
/// ```
/// If-Match = "*" / #entity-tag
/// ```
///
pub enum IfMatch {
    /// This is a way to check for the existence
    /// of the resource without caring about its
    /// specific version.
    Star,
    List(Vec<EntityTag>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IfRange {
    Tag(EntityTag),
    Date(Date),
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, EnumString, Debug, Display)]
#[derive_from_bits(u8)]
#[derive_to_bits(u8)]
#[repr(u8)]
pub enum MonthName {
    Jan = 1,
    Feb,
    Mar,
    Apr,
    May,
    Jun,
    Jul,
    Aug,
    Sep,
    Oct,
    Nov,
    Dec,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[derive_to_bits(u8)]
#[repr(transparent)]
pub struct Day(u8);

#[repr(transparent)]
pub struct Month(u8);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[derive_to_bits(u16)]
#[repr(transparent)]
pub struct Year(u16);

///
/// time-of-day  = hour ":" minute ":" second
///
/// ; 00:00:00 - 23:59:60 (leap second)
///
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TimeOfDay {
    hour: u8,
    minute: u8,
    second: u8,
}

////////////////////////////////////////
//// Range Requests

#[derive(Debug)]
pub struct RangesSpecifier {
    pub unit: RangeUnit,
    pub set: NonEmpty<RangeSpec>
}

#[derive(PartialEq, Eq)]
pub enum RangeSpec {
    IntRange {
        start: u64,
        end: Option<u64>
    },
    SuffixRange {
        end: u64
    },
    OtherRange(ByteString)
}

#[derive(Debug, Display, EnumIter, PartialEq, Eq)]
#[strum(ascii_case_insensitive, serialize_all = "lowercase")]
pub enum RangeUnit {
    Bytes,
    #[strum(default)]
    Custom(CaseInsensitiveString),
}

#[derive(Debug, Deref, DerefMut)]
pub struct AcceptRanges {
    value: NonEmpty<RangeUnit>
}

///
/// ```abnf
/// range-resp      = incl-range "/" ( complete-length / "*" )
/// incl-range      = first-pos "-" last-pos
/// complete-length = 1*DIGIT
/// ```
///
#[derive(Debug, PartialEq, Eq)]
pub struct RangeResp {
    pub range: RangeInclusive<u64>,
    /// None for unknown
    pub complete_length: Option<u64>
}

/// ```abnf
/// Content-Range     = range-unit SP range_or_unsatisfied
/// ```
#[derive(Debug, PartialEq, Eq)]
pub struct ContentRange {
    pub unit: RangeUnit,
    pub range_or_unsatisfied: RangeOrUnsatisfied
}

/// ```abnf
/// range_or_unsatisfied = ( range-resp / unsatisfied-range )
/// unsatisfied-range    = "*/" complete-length
/// complete-length      = 1*DIGIT
/// ```
#[derive(Debug, PartialEq, Eq)]
pub enum RangeOrUnsatisfied {
    Range(RangeResp),
    Unsatisfied(u64)
}

///
/// ```no_main
/// Server = product *( RWS ( product / comment ) )
/// ```
///
#[derive(Debug, Clone)]
pub struct Server {
    pub product: Product,
    pub rem: Vec<ProductOrComment>,
}

///
/// ```no_main
/// User-Agent = product *( RWS ( product / comment ) )
/// ```
///
#[derive(Debug, Clone)]
pub struct UserAgent {
    pub product: Product,
    pub rem: Vec<ProductOrComment>,
}

#[derive(Debug, Clone)]
pub enum ProductOrComment {
    Product(Product),
    Comment(ByteString),
}

///
/// ```no_main
/// product = token [ "/" product-version ]
/// product-version = token
/// ```
#[derive(Debug, Clone)]
pub struct Product {
    pub name: String,
    pub version: Option<String>,
}


////////////////////////////////////////////////////////////////////////////////
//// Implementations

impl Response {
    /// Builder mode
    pub fn field(self, filed: Field) -> Self {
        let mut mut_self = self;

        mut_self.fields.values.push(filed);

        mut_self
    }

    pub fn closed(&self) -> bool {
        self.fields.closed()
    }
}

impl Request {
    pub fn from_parts(request_line: RequestLine, fields: Fields) -> Self {
        let RequestLine {
            method,
            target,
            version,
        } = request_line;

        Self {
            method,
            target,
            version,
            fields,
        }
    }

    pub fn closed(&self) -> bool {
        self.fields.closed()
    }

    pub fn accept_encoding(&self) -> Option<&AcceptEncoding> {
        self.fields.accept_encoding()
    }
}

impl Message {
    pub fn fileds_mut(&mut self) -> &mut Fields {
        match self {
            Self::Request(request) => &mut request.fields,
            Self::Response(response) => &mut response.fields,
        }
    }
}

impl Fields {
    pub fn new() -> Self {
        Self { values: Vec::new() }
    }
}

impl Debug for Body {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "Empty"),
            Self::Complete(arg0) => f
                .debug_tuple("Complete")
                .field(&ByteStr::new(arg0))
                .finish(),
            Self::Chunked => write!(f, "Chunked"),
        }
    }
}

impl ChunkedBody {
    pub fn split_as_chunks(mut value: &ByteStr, limit: usize) -> Self {
        let mut chunks = Vec::new();

        let last_chunk = loop {
            let (next, rems) = value.split_at(limit.min(value.len()));

            if !next.is_empty() {
                chunks.push(next.into());
            }

            if rems.is_empty() {
                break rems.into();
            }

            value = rems;
        };

        Self {
            chunks,
            last_chunk,
            trailer_section: Fields::new(),
        }
    }
}

impl Chunk {
    pub fn from_parts(header: ChunkHeader, data: ByteString) -> Self {
        Self {
            size: header.size,
            ext: header.ext,
            data,
        }
    }

    pub fn is_last(&self) -> bool {
        self.size == 0
    }
}

impl From<&ByteStr> for Chunk {
    fn from(value: &ByteStr) -> Self {
        Self {
            size: value.len() as u32,
            ext: ChunkExt::new(),
            data: value.into(),
        }
    }
}

impl ChunkHeader {
    pub fn is_last(&self) -> bool {
        self.size == 0
    }
}

impl ChunkExt {
    pub fn new() -> Self {
        Self { value: Vec::new() }
    }
}

impl Display for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "close")
    }
}

impl CompleteRequest {
    pub fn from_parts(request: Request, body: Body) -> Self {
        Self { request, body }
    }
}

impl CompleteResponse {
    pub fn from_parts(response: Response, body: Body) -> Self {
        Self { response, body }
    }
}

impl Debug for EntityTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_weak {
            write!(f, "W/")?;
        }

        write!(f, "\"{}\"", self.opaque_tag)
    }
}

impl IfMatch {
    pub fn if_match(&self, tag: &EntityTag) -> bool {
        match self {
            IfMatch::Star => true,
            IfMatch::List(entity_tags) => entity_tags
                .iter()
                .find(|&here_tag| here_tag == tag)
                .is_some(),
        }
    }

    pub fn if_none_match(&self, tag: &EntityTag) -> bool {
        !self.if_match(tag)
    }
}

impl Allow {
    pub fn new() -> Self {
        Self { values: Vec::new() }
    }

    pub fn method(mut self, method: Method) -> Self {
        self.push(method);

        self
    }
}

impl AcceptEncoding {
    pub fn new() -> Self {
        Self {
            values: Default::default(),
        }
    }

    pub fn accept_coding(
        mut self,
        coding: Codings,
        opt_weight: Option<f32>,
    ) -> Self {
        self.push((coding, opt_weight));
        self
    }

    ///
    /// return a sorted by weight (trim weight = 0)
    ///
    pub fn priority_codings(&self) -> Vec<(Codings, f32)> {
        let mut options = self
            .values
            .iter()
            .filter_map(|(coding, q)| {
                if *q == Some(0.0) {
                    None
                }
                else {
                    Some((*coding, q.unwrap_or(1.0)))
                }
            })
            .collect::<Vec<_>>();

        // stable sort
        options.sort_by(|(_, q1), (_, q2)| q1.partial_cmp(q2).unwrap());

        options
    }

    ///
    /// weight = 0
    ///
    pub fn rejected_codings(&self) -> Vec<Codings> {
        self.values
            .iter()
            .filter_map(
                |(coding, q)| {
                    if *q == Some(0.0) { Some(*coding) } else { None }
                },
            )
            .collect::<Vec<_>>()
    }
}

impl Connection {
    pub fn new() -> Self {
        Self { value: Vec::new() }
    }

    pub fn connection(mut self, opt: ConnectionOption) -> Self {
        self.push(opt);
        self
    }
}

impl ContentEncoding {
    pub fn new() -> Self {
        Self { value: Vec::new() }
    }

    pub fn content_coding(mut self, coding: ContentCoding) -> Self {
        self.push(coding);
        self
    }
}

impl Debug for RangeSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IntRange { start, end } => {
                write!(f, "{start}-")?;

                if let Some(end) = end {
                    write!(f, "{end}")?;
                }
            },
            Self::SuffixRange { end } => {
                write!(f, "-{end}")?;
            },
            Self::OtherRange(arg0) => write!(f, "{arg0}")?,
        }

        Ok(())
    }
}

impl StatusCode {
    pub fn reason(&self) -> &str {
        use StatusCode::*;

        match self {
            Continue => "Continue",
            SwitchingProtocols => "Switching Protocols",
            Ok => "OK",
            Created => "Created",
            Accepted => "Accepted",
            NonAuthoriativeInfo => "Non-Authorizative Information",
            NonContent => "No Content",
            ResetContent => "Reset Content",
            PartialContent => "Partial Content",
            MultipleChoices => "Multiple Choices",
            MovePermanently => "Move Permanently",
            Found => "Found",
            SeeOther => "See Other",
            NotModified => "Not Modified",
            Deprecated305 => "",
            Deprecated306 => "",
            TemporaryRedirect => "Temporary Redirect",
            PermanentRedirect => "Permanent Redirect",
            BadRequest => "Bad Request",
            Unauthoriozed => "Unauthorized",
            PaymentRequired => "Payment Required",
            Forbidden => "Forbidden",
            NotFound => "Not Found",
            MethodNotAllowed => "Method Not Allowed",
            NotAcceptable => "Not Acceptable",
            ProxyAuthenticationRequired => "Proxy Authentication Required",
            RequestTimeout => "Request Timeout",
            Conflict => "Conflict",
            Gone => "Gone",
            LengthRequired => "Length Required",
            PreconditionFailed => "Precondition Failed",
            ContentTooLarge => "Content Too Large",
            URITooLong => "URI Too Long",
            UnsupportedMediaType => "Unsupported Media Type",
            RangeNotSatisfiable => "Range Not Satisfiable",
            ExpectationFailed => "Expectation Failed",
            April1Unused => "",
            MisdirectedRequest => "Misdirected Request",
            UnprocessableContent => "Unprocessable Content",
            UpgradeRequired => "Upgrade Required",
            InternalServerError => "Internal Server Error",
            NotImplemented => "Not Implemented",
            BadGateway => "Bad Gateway",
            ServiceUnavailable => "Service Unavailable",
            GatewayTimeout => "Gateway Timeout",
            HTTPVersionNotSupported => "HTTP Version Not Supported",
        }
    }
}

impl Fields {
    pub fn accept_encoding(&self) -> Option<&AcceptEncoding> {
        self.iter().find_map(|field| match field {
            Field::AcceptEncoding(accept_encoding) => Some(accept_encoding),
            _ => None,
        })
    }

    pub fn host(&self) -> Option<&Host> {
        self.values.iter().find_map(|field| match field {
            Field::Host(host) => Some(host),
            _ => None,
        })
    }

    pub fn trans_encoding(&self) -> Option<&TransferEncoding> {
        self.iter().find_map(|field| {
            if let Field::TransferEncoding(trans_encoding) = field {
                Some(trans_encoding)
            }
            else {
                None
            }
        })
    }

    pub fn content_length(&self) -> Option<u64> {
        self.iter().find_map(|field| {
            if let Field::ContentLength(content_length) = field {
                Some(*content_length)
            }
            else {
                None
            }
        })
    }

    pub fn content_type(&self) -> Option<&ContentType> {
        self.iter().find_map(|field| {
            if let Field::ContentType(content_type) = field {
                Some(content_type)
            }
            else {
                None
            }
        })
    }

    pub fn connection(&self) -> Option<&Connection> {
        self.values.iter().find_map(|field| {
            if let Field::Connection(connection) = field {
                Some(connection)
            }
            else {
                None
            }
        })
    }

    pub fn closed(&self) -> bool {
        self.connection()
            .map(|conn| {
                conn.iter()
                    .find(|opt| matches!(opt, ConnectionOption::Close))
            })
            .flatten()
            .is_some()
    }

    pub fn contains(&self, name: FieldName) -> bool {
        self.iter().find(|field| field.name() == name).is_some()
    }
}

impl From<Server> for UserAgent {
    fn from(value: Server) -> Self {
        Self {
            product: value.product,
            rem: value.rem,
        }
    }
}

impl From<UserAgent> for Server {
    fn from(value: UserAgent) -> Self {
        Self {
            product: value.product,
            rem: value.rem,
        }
    }
}

impl Display for Product {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)?;

        if let Some(ref version) = self.version {
            write!(f, "/{version}")?;
        }

        Ok(())
    }
}

impl Parameters {
    pub fn new() -> Self {
        Self { value: Vec::new() }
    }

    pub fn parameter(mut self, parameter: Parameter) -> Self {
        self.push(parameter);

        self
    }
}

impl TransferEncoding {
    pub fn new() -> Self {
        Self { value: Vec::new() }
    }

    pub fn transfer_coding(mut self, coding: TransferCoding) -> Self {
        self.push(coding);

        self
    }

    /// `chunked` exists in the last
    pub fn is_chunked(&self) -> bool {
        if let Some(coding) = self.last() {
            coding.coding == parameters::TransferCoding::Chunked
        }
        else {
            false
        }
    }
}

impl TransferCoding {
    pub fn chunked() -> Self {
        Self {
            coding: parameters::TransferCoding::Chunked,
            parameters: Parameters::new(),
        }
    }
}

impl Date {
    /// `Sun, 06 Nov 1994 08:49:37 GMT    ; IMF-fixdate`
    pub fn imf_fixdate(&self) -> String {
        format!(
            "{}, {:02} {} {:04} {} GMT",
            self.day_name,
            self.day.to_bits(),
            self.month,
            self.year.to_bits(),
            self.time_of_day
        )
    }

    pub fn naive_date(&self) -> NaiveDate {
        NaiveDate::from_ymd_opt(
            self.year.to_bits() as _,
            self.month.month(),
            self.day.to_bits() as _,
        )
        .unwrap()
    }

    pub fn naive_time(&self) -> NaiveTime {
        self.time_of_day.into()
    }

    pub fn naive_date_time(&self) -> NaiveDateTime {
        NaiveDateTime::new(self.naive_date(), self.naive_time())
    }
}

impl<Tz: TimeZone> From<DateTime<Tz>> for Date {
    fn from(value: DateTime<Tz>) -> Self {
        let date = value.date_naive();
        let time = value.time();

        Self {
            day_name: date.weekday().into(),
            month: MonthName::fetch_from(&date),
            day: Day::fetch_from(&date),
            year: Year::fetch_from(&date),
            time_of_day: time.into(),
        }
    }
}

impl From<Weekday> for DayName {
    fn from(value: Weekday) -> Self {
        unsafe { Self::from_u8(value.num_days_from_monday() as u8 + 1) }
    }
}

impl MonthName {
    fn fetch_from<D: Datelike>(value: &D) -> Self {
        unsafe { Self::from_u8(value.month0() as u8 + 1) }
    }

    pub fn month(&self) -> u32 {
        self.to_bits() as _
    }

    pub fn month0(&self) -> u32 {
        self.month() - 1
    }
}

impl Year {
    fn fetch_from<D: Datelike>(value: &D) -> Self {
        let (is_ad, year) = value.year_ce();

        debug_assert!(is_ad, "found ad year");
        debug_assert!(year <= 9999, "year out of range");

        Self(year as u16)
    }
}

impl Day {
    fn fetch_from<D: Datelike>(value: &D) -> Self {
        Self(value.day() as u8)
    }
}

impl<T: Timelike> From<T> for TimeOfDay {
    fn from(value: T) -> Self {
        let hour = value.hour() as u8;
        let minute = value.minute() as u8;
        let second = value.second() as u8;

        Self {
            hour,
            minute,
            second,
        }
    }
}

impl Into<NaiveTime> for TimeOfDay {
    fn into(self) -> NaiveTime {
        NaiveTime::from_hms_opt(
            self.hour as _,
            self.minute as _,
            self.second as _,
        )
        .unwrap()
    }
}

impl Display for TimeOfDay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:02}:{:02}:{:02}", self.hour, self.minute, self.second)
    }
}

impl Field {
    pub fn name(&self) -> FieldName {
        use FieldName::*;

        match self {
            Self::Host(..) => Host,
            Self::Connection(..) => Connection,
            Self::ContentType(..) => ContentType,
            Self::ContentEncoding(..) => ContentEncoding,
            Self::ContentLength(..) => ContentLength,
            Self::TransferEncoding(..) => TransferEncoding,
            Self::Allow(..) => Allow,
            Self::Accept(..) => Accept,
            Self::AcceptEncoding(..) => AcceptEncoding,
            Self::Server(..) => Server,
            Self::Date(..) => Date,
            Self::ETag(..) => ETag,
            Self::IfMatch(..) => IfMatch,
            Self::IfNoneMatch(..) => IfNoneMatch,
            Self::IfModifiedSince(..) => IfModifiedSince,
            Self::IfUnmodifiedSince(..) => IfUnmodifiedSince,
            Self::IfRange(..) => IfRange,
            Self::Range(..) => Range,
            Self::AcceptRanges(..) => AcceptRanges,
            Self::ContentRange(..)  => ContentRange,
            Self::UserAgent(..) => UserAgent,
            Self::NonStandard(RawField { name, .. }) => {
                NonStandard(CaseInsensitiveString::new(name))
            }
        }
    }
}

impl TryFrom<u16> for StatusCode {
    type Error = Box<str>;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            100..=101
            | 200..=206
            | 300..=308
            | 400..=418
            | 421..=422
            | 426
            | 500..=505 => Ok(unsafe { transmute(value) }),
            _ => {
                Err(format!("Unknown status code {}", value).into_boxed_str())
            }
        }
    }
}


#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn verify_strnum_usage() {
        assert_eq!(
            FieldName::ContentType.to_string(),
            "Content-Type".to_owned()
        );
        assert_eq!(
            "Content-Type".parse::<FieldName>().unwrap(),
            FieldName::ContentType
        );
        assert_eq!(
            "content-type".parse::<FieldName>().unwrap(),
            FieldName::ContentType
        );
        assert_eq!(
            "AbC".to_owned(),
            FieldName::NonStandard(CaseInsensitiveString::new("AbC"))
                .to_string()
        );
        assert_eq!(
            "abc".parse::<FieldName>().unwrap(),
            FieldName::NonStandard(CaseInsensitiveString::new("AbC"))
        );
    }

    #[test]
    fn verify_slice_usage() {
        let v = vec![1];
        assert_eq!(&v[1..], &[]); // allow
        assert_eq!(&v[2..], &[]); // range overflow
    }

    #[test]
    fn verify_num_parse() {
        assert_eq!("02".parse::<usize>().unwrap(), 2);
        assert!(" 2".parse::<usize>().is_err());
        assert_eq!("2".parse::<usize>().unwrap(), 2);

        assert_eq!("1.000".parse::<f32>().unwrap(), 1.000);
        assert_eq!("0.8".parse::<f32>().unwrap(), 0.8);

        assert_eq!(u32::from_str_radix("054A", 16).unwrap(), 0x054A);
    }

    #[test]
    fn verify_num_write() {
        assert_eq!(1.0f32.to_string(), "1.0");
    }

    #[test]
    fn verify_to_string() {
        use std::ascii::Char::*;

        assert_eq!(b'/'.to_string(), "47");
        assert_eq!(Solidus.as_str(), "/");

        let name = FieldName::NonStandard(CaseInsensitiveString::new("asdd"));

        let name_origin = name.clone();
        let name_s: &'static str = name.into();

        println!("{name_origin}/{name_s}");
    }
}
