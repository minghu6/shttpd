use std::{
    collections::HashMap,
    fmt::{Debug, Display},
    mem::transmute,
    num::ParseIntError,
    ops::Deref,
    str::FromStr,
    string::ToString,
};

use chrono::{DateTime, Datelike, TimeZone, Timelike, Weekday};
use m6ptr::ByteStr;
pub use m6ptr::FlatCow;
use m6tobytes::{derive_from_bits, derive_to_bits};
use parameters::ContentCoding;
pub use parsing::*;
use strum::{Display, EnumString};
use url::Url;

use super::{charset, mime};

pub mod parsing;
pub mod writing;

////////////////////////////////////////////////////////////////////////////////
//// Constants

const SP: char = 0x20 as char;
const COMMA: char = ',' as char;
const HYPHEN: char = '-' as char;

////////////////////////////////////////////////////////////////////////////////
//// Structures

#[derive(Debug)]
pub enum Message<'a> {
    Request(Request<'a>),
    Response(Response<'a>),
}

#[derive(Debug)]
pub struct Request<'a> {
    pub method: Method,
    pub target: RequestTarget,
    pub version: Version,
    pub fields: Fields<'a>,
    pub body: FlatCow<'a, ByteStr>,
    pub trailer: Option<Fields<'a>>
}

#[derive(Debug)]
pub struct Response<'a> {
    pub version: Version,
    pub status: StatusCode,
    pub reason: Option<Box<str>>,
    pub fields: Fields<'a>,
    pub body: FlatCow<'a, ByteStr>,
    pub trailer: Option<Fields<'a>>
}

#[derive(Debug)]
pub enum MessageHeader<'a> {
    RequestHeader(RequestHeader<'a>),
    ResponseHeader(ResponseHeader<'a>),
}

#[derive(Debug)]
pub struct RequestHeader<'a> {
    pub method: Method,
    pub target: RequestTarget,
    pub version: Version,
    pub fields: Fields<'a>,
}

#[derive(Debug)]
pub struct ResponseHeader<'a> {
    pub version: Version,
    pub status: StatusCode,
    pub reason: Option<Box<str>>,
    pub fields: Fields<'a>,
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RequestTarget {
    ///
    /// example: GET /where?q=now HTTP/1.1
    ///
    /// absolute path ['?' query]
    ///
    /// When making a request directly to an origin server,
    /// other than a CONNECT or server-wide OPTIONS request (as detailed below)
    Origin {
        path: Box<str>,
        query: Option<Box<str>>,
    },
    /// absolute uri
    ///
    /// When making a request to a proxy,
    /// other than a CONNECT or server-wide OPTIONS request (as detailed below)
    Absolute { uri: Url },
    ///
    ///
    /// CONNECT www.example.com:80 HTTP/1.1
    ///
    Authority { host: Box<str>, port: u16 },
    /// example: OPTIONS * HTTP/1.1
    ///
    /// is only used for a server-wide OPTIONS request
    Asterisk,
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

#[derive(Debug)]
pub struct Fields<'a> {
    pub fields: Vec<Field<'a>>,
}

#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, EnumString, Display,
)]
#[strum(ascii_case_insensitive)]
pub enum FieldName {
    #[strum(serialize = "Accept")]
    Accept,
    Connection,
    #[strum(serialize = "Content-Type")]
    ContentType,
    #[strum(serialize = "Content-Encoding")]
    ContentEncoding,
    #[strum(serialize = "Date")]
    Date,
    #[strum(serialize = "Host")]
    Host,
    #[strum(serialize = "Server")]
    Server,
    #[strum(serialize = "Transfer-Encoding")]
    TransferEncoding,

    #[strum(serialize = "{0}", default)]
    NonStandard(Box<str>),
}

#[derive(Debug)]
pub struct Host<'a> {
    pub host: FlatCow<'a, str>,
    pub port: Option<u16>,
}

#[derive(Debug)]
pub enum Field<'a> {
    Accept(Accept<'a>),
    /// Connection: close
    Connection,
    ContentType(MediaType<'a>),
    ContentEncoding(ContentEncoding),
    Date(Date),
    Host(Host<'a>),
    Server(Server<'a>),
    TransferEncoding(TransferEncoding<'a>),
    NonStandard(RawField<'a>),
}

/// derive trait `Ord` based on
/// [lexicographic order]
/// (https://doc.rust-lang.org/std/cmp/trait.Ord.html#derivable)
/// which is name here.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RawField<'a> {
    pub name: FlatCow<'a, str>,
    pub value: Vec<FlatCow<'a, ByteStr>>,
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
#[derive(Debug, PartialEq, Eq)]
pub struct Parameters<'a> {
    value: HashMap<FlatCow<'a, str>, ParameterValue<'a>>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ParameterValue<'a> {
    Token(FlatCow<'a, str>),
    QStr(FlatCow<'a, ByteStr>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SingletonFieldValue<'a> {
    Token(FlatCow<'a, str>),
    QStr(FlatCow<'a, [u8]>),
    Oth(FlatCow<'a, [u8]>),
}

#[derive(Debug, PartialEq, Eq)]
pub struct MediaType<'a> {
    mime: mime::MediaType,
    parameters: Parameters<'a>,
}

#[derive(Debug)]
pub struct MediaRange<'a> {
    pub mime: mime::MediaRangeType,
    pub parameters: Parameters<'a>,
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
#[derive(Debug)]
pub struct Accept<'a> {
    pub values: Vec<(MediaRange<'a>, f32)>,
}

/// deprecated field (for utf-8 has become nearly ubiquitous)
pub struct AcceptCharset {
    pub values: Vec<(Charset, f32)>,
}

pub struct Connection;

pub enum Charset {
    Spec(charset::Charset),
    Star,
}

pub type ContentType<'a> = MediaType<'a>;

pub struct ContentLength {
    pub value: u64,
}

#[derive(Debug)]
pub struct ContentEncoding {
    pub value: Vec<ContentCoding>,
}

///
///
/// ```ABNF
/// transfer-coding    = token *( OWS ";" OWS transfer-parameter )
/// transfer-parameter = token BWS "=" BWS ( token / quoted-string )
/// ```
///
#[derive(Debug)]
pub struct TransferEncoding<'a> {
    pub value: Vec<TransferCoding<'a>>,
}

#[derive(Debug)]
pub struct TransferCoding<'a> {
    pub coding: parameters::TransferCoding,
    pub parameters: Parameters<'a>,
}

pub mod parameters {
    use strum::EnumString;

    ///
    /// According to [IANA Hypertext Transfer Protocol (HTTP) Parameters
    /// ](https://www.iana.org/assignments/http-parameters/http-parameters.xhtml)
    ///
    #[derive(Debug, Clone, Copy, PartialEq, Eq, EnumString)]
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
    #[derive(Debug, Clone, Copy, PartialEq, Eq, EnumString)]
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
pub struct Server<'a> {
    pub product: Product<'a>,
    pub rem: Vec<ProductOrComment<'a>>,
}

#[derive(Debug, Clone)]
pub enum ProductOrComment<'a> {
    Product(Product<'a>),
    Comment(FlatCow<'a, ByteStr>),
}

///
/// ```no_main
/// product = token [ "/" product-version ]
/// product-version = token
/// ```
#[derive(Debug, Clone)]
pub struct Product<'a> {
    pub name: FlatCow<'a, str>,
    pub version: Option<FlatCow<'a, str>>,
}

////////////////////////////////////////////////////////////////////////////////
//// Implementations

impl<'a> MessageHeader<'a> {
    pub fn fileds_mut(&mut self) -> &mut Fields<'a> {
        use MessageHeader::*;

        match self {
            RequestHeader(header) => &mut header.fields,
            ResponseHeader(header) => &mut header.fields,
        }
    }
}

impl<'a> Message<'a> {
    pub fn from_parts(
        header: MessageHeader<'a>,
        body: FlatCow<'a, ByteStr>,
        trailer: Option<Fields<'a>>,
    ) -> Self {
        use MessageHeader::*;

        match header {
            RequestHeader(header) => Self::Request(Request {
                method: header.method,
                target: header.target,
                version: header.version,
                fields: header.fields,
                body,
                trailer
            }),
            ResponseHeader(header) => {
                Self::Response(Response {
                    version: header.version,
                    status: header.status,
                    reason: header.reason,
                    fields: header.fields,
                    body,
                    trailer
                })
            }
        }
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

impl<'a> Fields<'a> {
    pub fn host(&self) -> Option<&Host<'a>> {
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
}

impl<'a> Deref for Fields<'a> {
    type Target = [Field<'a>];

    fn deref(&self) -> &Self::Target {
        &self.fields
    }
}

impl Display for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "close")
    }
}

impl Deref for ContentEncoding {
    type Target = [ContentCoding];

    fn deref(&self) -> &Self::Target {
        &self.value
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

impl FromStr for Date {
    type Err = ();

    fn from_str(mut s: &str) -> Result<Self, Self::Err> {
        macro_rules! or_else {
            ($e:expr) => {
                $e.map_err(|_| ())?
            };
        }

        macro_rules! require {
            ($r:expr, $c:ident) => {
                if s[$r] == $c.to_string() {
                    Err(())?
                }
            };
            ($r:expr, =$s:literal) => {
                if &s[$r] == $s {
                    Err(())?
                }
            };
        }

        let Some(day_name_pos) = s.find(&[SP, COMMA])
        else {
            Err(())?
        };

        let day_name = or_else!(s[..day_name_pos].parse::<DayName>());

        let s_rem_len = s[day_name_pos + 1..].len();

        if &s[day_name_pos..day_name_pos + 1] == "," {
            // IMF-fixdate or obsolete RFC 850 format
            if s_rem_len == 1 + 2 + 1 + 3 + 1 + 4 + 1 + 8 + 1 + 3 {
                s = &s[day_name_pos + 1..];

                require!(..1, SP);

                let day = or_else!(s[1..3].parse::<Day>());

                require!(3..4, SP);

                let month = or_else!(s[4..7].parse::<MonthName>());

                require!(7..8, SP);

                let year = or_else!(s[8..12].parse::<Year>());

                require!(12..13, SP);

                let time_of_day = or_else!(s[13..21].parse::<TimeOfDay>());

                require!(21..22, SP);

                require!(22..25, ="GMT");

                Ok(Self {
                    day_name,
                    month,
                    day,
                    year,
                    time_of_day,
                })
            }
            // obsolete RFC 850 format
            else if s_rem_len == 1 + 2 + 1 + 3 + 1 + 2 + 1 + 8 + 1 + 3 {
                s = &s[day_name_pos + 1..];

                require!(..1, SP);

                let day = or_else!(s[1..3].parse::<Day>());

                require!(3..4, HYPHEN);

                let month = or_else!(s[4..7].parse::<MonthName>());

                require!(7..8, HYPHEN);

                let year = or_else!(s[8..10].parse::<Year>());

                require!(10..12, SP);

                let time_of_day = or_else!(s[12..20].parse::<TimeOfDay>());

                require!(20..21, SP);

                require!(21..24, ="GMT");

                Ok(Self {
                    day_name,
                    month,
                    day,
                    year,
                    time_of_day,
                })
            }
            else {
                Err(())
            }
        }
        else {
            if s_rem_len != 3 + 1 + 2 + 1 + 8 + 1 + 4 {
                Err(())?;
            }

            // ANSI C's asctime() format
            s = &s[day_name_pos + 1..];

            let month = or_else!(s[..3].parse::<MonthName>());

            require!(3..4, SP);

            let day = or_else!(s[4..6].trim_start().parse::<Day>());

            require!(6..7, SP);

            let time_of_day = or_else!(s[7..15].parse::<TimeOfDay>());

            require!(15..16, SP);

            let year = or_else!(s[16..20].parse::<Year>());

            Ok(Self {
                day_name,
                month,
                day,
                year,
                time_of_day,
            })
        }
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

impl FromStr for Year {
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.parse::<u16>()?))
    }
}

impl Day {
    fn fetch_from<D: Datelike>(value: &D) -> Self {
        Self(value.day() as u8)
    }
}

impl FromStr for Day {
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.parse::<u8>()?))
    }
}

impl FromStr for TimeOfDay {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 8 {
            Err(())?
        }

        let hour = s[0..2].parse().map_err(|_| ())?;

        if &s[2..3] != ":" {
            Err(())?
        }

        let minute = s[3..5].parse().map_err(|_| ())?;

        if &s[5..6] != ":" {
            Err(())?
        }

        let second = s[6..8].parse().map_err(|_| ())?;

        Ok(TimeOfDay {
            hour,
            minute,
            second,
        })
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

impl<'a> Field<'a> {
    pub fn name(&self) -> FieldName {
        use FieldName::*;

        match self {
            Self::Host(..) => Host,
            Self::Connection => Connection,
            Self::ContentType(..) => ContentType,
            Self::ContentEncoding(..) => ContentEncoding,
            Self::TransferEncoding(..) => TransferEncoding,
            Self::Accept(..) => Accept,
            Self::Server(..) => Server,
            Self::Date(..) => Date,
            Self::NonStandard(RawField { name, .. }) => {
                NonStandard(name.to_string().into_boxed_str())
            }
        }
    }
}

impl<'a> Parameters<'a> {}

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

impl FromStr for StatusCode {
    type Err = Box<str>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse::<u16>()
            .map_err(|err| err.to_string().into_boxed_str())
            .and_then(|uint| uint.try_into())
    }
}

impl RequestTarget {
    pub fn path(&self) -> &str {
        use RequestTarget::*;

        match self {
            Origin { path, .. } => path,
            Absolute { uri } => uri.path(),
            Authority { .. } => "/",
            Asterisk => "/",
        }
    }

    pub fn query(&self) -> Option<&str> {
        use RequestTarget::*;

        match self {
            Origin { query, .. } => query.as_ref().map(|s| s.deref()),
            Absolute { uri } => uri.query(),
            Authority { .. } => None,
            Asterisk => None,
        }
    }
}

impl<'a> FromStr for Host<'a> {
    type Err = Box<str>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let url =
            Url::parse(s).map_err(|err| err.to_string().into_boxed_str())?;

        let Some(host) = url.host_str()
        else {
            Err("No Host".to_string().into_boxed_str())?
        };

        //
        Ok(Self {
            host: FlatCow::<str>::own_new(host.to_owned()),
            port: url.port(),
        })
    }
}

impl FromStr for RequestTarget {
    type Err = Box<str>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "*" {
            return Ok(Self::Asterisk);
        }

        let url =
            Url::parse(s).map_err(|err| err.to_string().into_boxed_str())?;

        Ok(if let Some(host) = url.host_str() {
            if let Some(port) = url.port()
                && url.path() == "/"
            {
                Self::Authority {
                    host: host.to_string().into_boxed_str(),
                    port,
                }
            }
            else {
                Self::Absolute { uri: url }
            }
        }
        else {
            Self::Origin {
                path: url.path().to_owned().into_boxed_str(),
                query: url.query().map(|q| q.to_owned().into_boxed_str()),
            }
        })
    }
}

impl<'a> Response<'a> {
    /// Builder mode
    pub fn field(self, filed: Field<'a>) -> Self {
        let mut mut_self = self;

        mut_self.fields.fields.push(filed);

        mut_self
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
            "ABC".to_owned(),
            FieldName::NonStandard("ABC".to_owned().into_boxed_str())
                .to_string()
        );
        assert_eq!(
            "ABC".parse::<FieldName>().unwrap(),
            FieldName::NonStandard("ABC".to_owned().into_boxed_str())
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
    }
}
