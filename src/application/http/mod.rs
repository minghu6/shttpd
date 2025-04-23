use std::{
    fmt::{Debug, Display},
    mem::transmute,
    num::ParseIntError,
    string::ToString,
};

use chrono::{DateTime, Datelike, TimeZone, Timelike, Weekday};
use derive_more::derive::{Deref, DerefMut};
pub use m6io::FlatCow;
use m6io::{ByteStr, ByteString};
use m6tobytes::{derive_from_bits, derive_to_bits};
pub use nonempty::NonEmpty;
use parameters::ContentCoding;
use strum::{Display, EnumString};
pub use case_insensitive_string::CaseInsensitiveString;
use uri::RequestTarget;
use super::{charset, mime};

pub mod parsing;
pub mod writing;
pub mod uri;

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

#[derive(Debug)]
pub enum Body {
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
    pub fields: Vec<Field>,
}

#[derive(
    Debug, Clone, PartialEq, Eq, Hash, EnumString, Display,
)]
#[strum(
    ascii_case_insensitive,
    parse_err_fn = to_infalliable,
    parse_err_ty = Infallible
)]
pub enum FieldName {
    #[strum(serialize = "Accept")]
    Accept,
    Connection,
    #[strum(serialize = "Content-Type")]
    ContentType,
    #[strum(serialize = "Content-Encoding")]
    ContentEncoding,
    #[strum(serialize = "Content-Length")]
    ContentLength,
    #[strum(serialize = "Date")]
    Date,
    #[strum(serialize = "Host")]
    Host,
    #[strum(serialize = "Server")]
    Server,
    #[strum(serialize = "Transfer-Encoding")]
    TransferEncoding,
    #[strum(serialize = "Range")]
    Range,
    #[strum(serialize = "Accept-Ranges")]
    AcceptRanges,
    #[strum(serialize = "Content-Range")]
    ContentRange,
    #[strum(default)]
    NonStandard(CaseInsensitiveString),
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

#[derive(Debug)]
pub enum Field {
    Accept(Accept),
    /// Connection: close
    Connection(Connection),
    ContentType(MediaType),
    ContentEncoding(ContentEncoding),
    ContentLength(u64),
    Date(Date),
    Host(Host),
    Server(Server),
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
/// xx=yy ; mm=nn ...
///
/// ```abnf
/// parameters      = *( OWS ";" OWS [ parameter ] )
/// parameter       = parameter-name "=" parameter-value
/// parameter-name  = token
/// parameter-value = ( token / quoted-string )
/// ```
#[derive(Debug, Deref, DerefMut)]
pub struct Parameters {
    value: Vec<Parameter>,
}

#[derive(Debug)]
pub struct Parameter {
    pub name: String,
    pub value: ParameterValue,
}

#[derive(Debug, PartialEq, Eq)]
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
#[derive(Debug)]
pub struct MediaType {
    pub mime: mime::MediaType,
    pub parameters: Parameters,
}

#[derive(Debug)]
pub struct MediaRange {
    pub mime: mime::MediaRangeType,
    pub parameters: Parameters,
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
    pub values: NonEmpty<(MediaRange, f32)>,
}

/// deprecated field (for utf-8 has become nearly ubiquitous)
pub struct AcceptCharset {
    pub values: NonEmpty<(Charset, f32)>,
}

pub enum Charset {
    Spec(charset::Charset),
    Star,
}

pub type ContentType = MediaType;

pub struct ContentLength {
    pub value: u64,
}

#[derive(Debug, Deref)]
pub struct ContentEncoding {
    pub value: NonEmpty<ContentCoding>,
}

#[derive(Debug, Deref, DerefMut)]
pub struct Connection {
    pub value: NonEmpty<ConnectionOption>,
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
    pub value: NonEmpty<TransferCoding>,
}

///
///
/// ```ABNF
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
    #[strum(ascii_case_insensitive)]
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
        /// "no encoding", identity(x) = x
        Identity,
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
    value: Vec<ValueOrPair>,
}

#[derive(Debug)]
pub enum ValueOrPair {
    Value(String),
    Pair(Parameter),
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
#[derive(Debug)]
pub struct Date {
    pub day_name: DayName,
    pub month: MonthName,
    pub day: Day,
    pub year: Year,
    pub time_of_day: TimeOfDay,
}

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

#[derive(Clone, Copy, PartialEq, Eq, Hash, EnumString, Debug, Display)]
#[derive_from_bits(u8)]
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

        mut_self.fields.fields.push(filed);

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
}

impl Message {
    pub fn fileds_mut(&mut self) -> &mut Fields {
        match self {
            Self::Request(request) => &mut request.fields,
            Self::Response(response) => &mut response.fields,
        }
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

impl Connection {
    pub fn new(opt: ConnectionOption) -> Self {
        Self{ value: NonEmpty::new(opt) }
    }
}

impl ContentEncoding {
    pub fn from_vec(vec: Vec<ContentCoding>) -> Option<Self> {
        NonEmpty::from_vec(vec).map(|value| Self {value})
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
    pub fn host(&self) -> Option<&Host> {
        self.fields
            .iter()
            .find(|field| matches!(field, Field::Host(..)))
            .map(|field| {
                let Field::Host(host) = field
                else {
                    unreachable!()
                };
                host
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

    pub fn connection(&self) -> Option<&Connection> {
        self.fields.iter().find_map(|field| {
            if let Field::Connection(connection) = field {
                Some(connection)
            }
            else {
                None
            }
        })
    }

    pub fn closed(&self) -> bool {
        self.connection().map(|conn| {
            conn.iter()
                .find(|opt| matches!(opt, ConnectionOption::Close))
        }).flatten().is_some()
    }

    pub fn contains(&self, name: FieldName) -> bool {
        self.iter().find(|field| field.name() == name).is_some()
    }
}

impl Parameters {
    pub fn new() -> Self {
        Self { value: Vec::new() }
    }

    pub fn parameter(mut self, name: &str, value: ParameterValue) -> Self {
        self.push(Parameter {
            name: name.to_owned(),
            value,
        });

        self
    }
}

impl TransferEncoding {
    /// `chunked` exists in the last
    pub fn chunked(&self) -> bool {
        let coding = self.last();

        coding.coding == parameters::TransferCoding::Chunked
    }
}

impl ChunkHeader {}

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
            Self::Accept(..) => Accept,
            Self::Server(..) => Server,
            Self::Date(..) => Date,
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
    }
}
