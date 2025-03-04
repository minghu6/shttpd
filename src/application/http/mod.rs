use std::{
    collections::HashMap, mem::transmute, num::ParseIntError, str::FromStr,
    string::ToString,
};

use m6ptr::FlatCow;
use m6tobytes::derive_to_bits;
pub use parsing::*;
use strum::{Display, EnumString};
use url::Url;

use super::{charset, mime};

pub mod parsing;
pub mod request;
pub mod response;

////////////////////////////////////////////////////////////////////////////////
//// Constants

const SP: char = 0x20 as char;
const COMMA: char = ',' as char;
const HYPHEN: char = '-' as char;

////////////////////////////////////////////////////////////////////////////////
//// Structures

#[derive(Debug, Clone)]
pub enum Message<'a> {
    Request(Request<'a>),
    Response(Response<'a>),
}

#[derive(Debug, Clone)]
pub struct Request<'a> {
    pub method: Method,
    pub target: RequestTarget,
    pub version: Version,
    pub fields: Fields<'a>,
    pub body: &'a [u8],
}

#[derive(Debug, Clone)]
pub struct Response<'a> {
    pub version: Version,
    pub status: StatusCode,
    pub reason: Option<Box<str>>,
    pub fields: Fields<'a>,
    pub body: &'a [u8],
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
    /// absolute path ['?' query]
    Origin {
        path: Box<str>,
        query: Option<Box<str>>,
    },
    /// absolute uri
    Absolute {
        uri: Url,
    },
    Authority {
        host: Box<str>,
        port: u16,
    },
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


#[derive(Debug, Clone)]
pub struct Fields<'a> {
    pub fields: HashMap<FieldName, Field<'a>>,
}

#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, EnumString, Display,
)]
pub enum FieldName {
    #[strum(serialize = "Content-Type", ascii_case_insensitive)]
    ContentType,
    #[strum(serialize = "Accept", ascii_case_insensitive)]
    Accept,
    #[strum(serialize = "{0}", default)]
    NonSandard(Box<str>),
}

#[derive(Debug, Clone)]
pub enum Field<'a> {
    ContentType(MediaType<'a>),
    Accept(Accept<'a>),
    NonSandard(RawField<'a>),
}

/// derive trait `Ord` based on
/// [lexicographic order]
/// (https://doc.rust-lang.org/std/cmp/trait.Ord.html#derivable)
/// which is name here.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RawField<'a> {
    pub name: &'a str,
    pub value: Box<[FlatCow<'a, [u8]>]>,
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parameters<'a> {
    value: HashMap<FlatCow<'a, str>, Vec<ParameterValue<'a>>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParameterValue<'a> {
    Token(FlatCow<'a, str>),
    QStr(FlatCow<'a, [u8]>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SingletonFieldValue<'a> {
    Token(FlatCow<'a, str>),
    QStr(FlatCow<'a, [u8]>),
    Oth(FlatCow<'a, [u8]>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaType<'a> {
    mime: mime::MediaType,
    parameters: Parameters<'a>,
}

#[derive(Debug, Clone)]
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
#[derive(Debug, Clone)]
pub struct Accept<'a> {
    pub values: Vec<(MediaRange<'a>, f32)>,
}

/// deprecated field (for utf-8 has become nearly ubiquitous)
pub struct AcceptCharset {
    pub values: Vec<(Charset, f32)>,
}

pub enum Charset {
    Spec(charset::Charset),
    Star,
}

pub struct ContentType<'a> {
    pub value: MediaType<'a>,
}

pub struct ContentLength {
    pub value: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContentEncoding {
    value: ContentCoding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentCoding {
    GZip,
    Deflate,
    Compress,
    /// no encoding
    Identity,
}

///
/// [HTTP-date](https://datatracker.ietf.org/doc/html/rfc9110#name-date-time-formats)
///
/// HTTP-date    = IMF-fixdate / obs-date
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
pub struct Date {
    pub day_name: DayName,
    pub month: MonthName,
    pub day: u8,
    pub year: u8,
    pub time_of_day: TimeOfDay,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, EnumString, Display)]
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

#[derive(Clone, Copy, PartialEq, Eq, Hash, EnumString, Display)]
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

#[repr(transparent)]
pub struct Day(u8);

#[repr(transparent)]
pub struct Month(u8);

#[repr(transparent)]
pub struct Year(u8);

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


////////////////////////////////////////////////////////////////////////////////
//// Implementations

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

                let day = or_else!(s[1..3].parse::<u8>());

                require!(3..4, SP);

                let month = or_else!(s[4..7].parse::<MonthName>());

                require!(7..8, SP);

                let year = or_else!(s[8..12].parse::<u8>());

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

                let day = or_else!(s[1..3].parse::<u8>());

                require!(3..4, HYPHEN);

                let month = or_else!(s[4..7].parse::<MonthName>());

                require!(7..8, HYPHEN);

                let year = or_else!(s[8..10].parse::<u8>());

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

            let day = or_else!(s[4..6].trim_start().parse::<u8>());

            require!(6..7, SP);

            let time_of_day = or_else!(s[7..15].parse::<TimeOfDay>());

            require!(15..16, SP);

            let year = or_else!(s[16..20].parse::<u8>());

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

// impl Field {
//     pub fn name(&self) -> &str {
//         match self {
//             Self::NonSandard(raw) => &raw.name,
//         }
//     }
// }

impl<'a> Fields<'a> {
    // pub fn push(&mut self, field: Field) {
    //     match self.value.binary_search_by_key(&field.name(), |f| f.name()) {
    //         Ok(_idx) => unimplemented!(),
    //         Err(idx) => self.value.insert(idx, field),
    //     }
    // }
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
            FieldName::NonSandard("ABC".to_owned().into_boxed_str())
                .to_string()
        );
        assert_eq!(
            "ABC".parse::<FieldName>().unwrap(),
            FieldName::NonSandard("ABC".to_owned().into_boxed_str())
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
