use std::{
    borrow::Cow, collections::HashMap, mem::transmute, str::FromStr,
    string::ToString,
};

use m6parsing::Span;
use m6tobytes::derive_to_bits;
#[cfg(feature = "parse")]
pub use parsing::*;
use strum::{Display, EnumString};
use url::Url;

pub mod request;
pub mod response;


////////////////////////////////////////////////////////////////////////////////
//// Structures

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message<'a> {
    Request(Request<'a>),
    Response(Response<'a>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request<'a> {
    method: Method,
    target: RequestTarget,
    version: Version,
    // fields: Fields<'static>,
    body: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response<'a> {
    version: Version,
    status: StatusCode,
    reason: Option<Box<str>>,
    // fields: Fields<'static>,
    body: &'a [u8],
}

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

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, EnumString,
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


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fields<'a> {
    value: HashMap<FieldName, Field<'a>>,
}

#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, EnumString, Display,
)]
pub enum FieldName {
    #[strum(serialize = "Content-Type")]
    ContentType,
    #[strum(serialize = "{0}", default)]
    NonSandard(Box<str>),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Field<'a> {
    NonSandard(RawField<'a>),
}

// derive trait `Ord` based on
// [lexicographic order](https://doc.rust-lang.org/std/cmp/trait.Ord.html#derivable)
// which is name here.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RawField<'a> {
    pub name: Cow<'a, str>,
    pub value: Box<[Cow<'a, [u8]>]>,
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
    value: HashMap<&'a str, Vec<ParameterValue<'a>>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParameterValue<'a> {
    Token(&'a str),
    QStr(Cow<'a, [u8]>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SingletonFieldValue<'a> {
    Token(Cow<'a, str>),
    QStr(Cow<'a, [u8]>),
    Oth(Cow<'a, [u8]>),
}

pub struct MediaType {

}

////////////////////////////////////////////////////////////////////////////////
//// Implementations

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


////////////////////////////////////////////////////////////////////////////////
//// Embedded Mods

///
/// Refer:
///
/// 1. [RFC-5234 - Augmented BNF for Syntax Specifications: ABNF](https://datatracker.ietf.org/doc/html/rfc5234)
///
/// 1. [RFC-9110 - HTTP Semantics](https://datatracker.ietf.org/doc/html/rfc9110)
///
/// 1. [RFC-9112 - HTTP/1.1](https://datatracker.ietf.org/doc/html/rfc9112)
///
#[cfg(feature = "parse")]
mod parsing {

    use std::{
        borrow::Cow,
        collections::{HashMap, hash_map::Entry},
        convert::Infallible,
        error::Error,
        ops::Deref,
        str::{FromStr, from_utf8_unchecked},
    };

    use ParseErrorReason::*;
    use derive_more::derive::Display;
    use m6parsing::Span;

    use super::*;


    macro_rules! ALPHA {
        () => {
            b'a'..=b'z' | b'A'..=b'Z'
        };
    }

    macro_rules! DIGIT {
        () => {
            b'0'..=b'9'
        };
    }

    /// obs-text, obsoleted chars, viewed as opaque data
    macro_rules! OBS_TEXT {
        () => {
            0x80..=0xFF
        };
    }

    /// VCHAR exclude delimiters
    macro_rules! TCHAR {
        () => {
            b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' |
            b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~' |
            DIGIT![] | ALPHA![]
        };
    }

    /// `"(),/:;<=>?@[\]{}"`
    macro_rules! DELIMITERS_EX_PAREN {
        () => {
            // b'(' | b')'
            b',' | b'/'
                | b':'
                | b';'
                | b'<'
                | b'='
                | b'>'
                | b'?'
                | b'@'
                | b'['
                | b']'
                | b'\\'
                | b'{'
                | b'}'
        };
    }

    macro_rules! WS {
        () => {
            SP | HTAB
        };
    }

    /// visable ascii char
    macro_rules! VCHAR {
        () => {
            0x21..=0x7E
        };
    }

    pub const STANDARD: ParseOptions = ParseOptions {
        // skip_invalid_char: false,
        // quote_anychar: true,
        // strict_space: true,
    };

    const HTAB: u8 = 0x09;
    const SP: u8 = 0x20;
    // 13
    const CR: u8 = b'\n';
    // 10
    const LF: u8 = b'\r';
    const DQUOTE: u8 = b'"';
    const CRLF: &[u8] = b"\n\r";
    const LPAREN: u8 = b'(';
    const RPAREN: u8 = b')';
    const BACKSLASH: u8 = b'\\';


    pub struct ParseOptions {
        // skip_invalid_char: bool,
        // quote_anychar: bool,
        // strict_space: bool,
        // allow_empty_field_value: bool
    }

    #[derive(Debug, Display)]
    #[display("{self:?}")]
    pub struct ParseError {
        reason: ParseErrorReason,
        span: Span,
    }

    #[derive(Debug, Display)]
    pub enum ParseErrorReason {
        LackCRLF,
        /// `\n` without followed by `\r`
        UncoupledCR,
        InvalidStartLine,
        InvalidFieldLine(FieldName),
    }

    enum StartLine {
        RequestLine {
            method: Method,
            target: RequestTarget,
            version: Version,
        },
        StatusLine {
            version: Version,
            status: StatusCode,
            reason: Option<Box<str>>,
        },
    }

    struct MaybeBoxedStr {
        value: Option<Box<str>>,
    }

    // enum FieldValue<'a> {
    //     Singleton(Cow<'a, [u8]>),
    //     List(Vec<Member<'a>>)
    // }

    // pub enum Member<'a> {
    //     Parameters(Parameters<'a>),
    //     Singleton(SingletonFieldValue<'a>),
    // }

    type RawFields<'a> = HashMap<&'a str, Vec<RawFieldValue<'a>>>;

    struct RawFieldValue<'a> {
        value: Cow<'a, [u8]>,
        span: Span,
    }

    enum CowBuf<'a> {
        Slice {
            value: &'a [u8],
            start: usize,
            end: usize,
        },
        Owned {
            value: Vec<u8>,
        },
    }

    impl<'a> CowBuf<'a> {
        fn init(value: &'a [u8]) -> Self {
            Self::Slice {
                value,
                start: 0,
                end: 0,
            }
        }

        fn to_cow_slice(self) -> Cow<'a, [u8]> {
            match self {
                Self::Slice { value, start, end } => {
                    Cow::Borrowed(&value[start..end])
                }
                Self::Owned { value } => Cow::Owned(value),
            }
        }

        fn start(&mut self, i: usize) {
            let Self::Slice { start, end, .. } = self
            else {
                unreachable!()
            };

            *start = i;
            *end = i;
        }

        fn push(&mut self, b: u8) {
            match self {
                Self::Slice { end, .. } => *end += 1,
                Self::Owned { value } => value.push(b),
            }
        }

        fn clone_push(&mut self, b: u8) {
            match *self {
                Self::Slice { value, start, end } => {
                    let mut owned = value[start..end].to_owned();
                    owned.push(b);
                    *self = Self::Owned { value: owned }
                }
                Self::Owned { ref mut value } => {
                    value.push(b);
                }
            }
        }
    }

    impl<'a> Deref for RawFieldValue<'a> {
        type Target = Cow<'a, [u8]>;

        fn deref(&self) -> &Self::Target {
            &self.value
        }
    }

    impl Error for ParseError {}

    impl FromStr for MaybeBoxedStr {
        type Err = Infallible;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            Ok(Self {
                value: if s.is_empty() {
                    Some(s.to_owned().into_boxed_str())
                }
                else {
                    None
                },
            })
        }
    }

    impl ParseOptions {
        pub fn parse<'a>(
            &self,
            bytes: &'a [u8],
        ) -> Result<Message<'a>, ParseError> {
            /* parse startline */

            let (startline, offset_startline) = self.parse_startline(bytes)?;

            /* parse fields */

            let (raw_fields, offset_fields) = self
                .parse_raw_fields(&bytes[offset_startline..])
                .map_err(|mut err| {
                    err.span >>= offset_startline;
                    err
                })?;

            let body = &bytes[offset_startline + offset_fields..];

            Ok(match startline {
                StartLine::RequestLine {
                    method,
                    target,
                    version,
                } => Message::Request(Request {
                    method,
                    target,
                    version,
                    // fields,
                    body,
                }),
                StartLine::StatusLine {
                    version,
                    status,
                    reason,
                } => Message::Response(Response {
                    version,
                    status,
                    reason,
                    // fields,
                    body,
                }),
            })
        }

        ///
        /// first byte is double-quote
        ///
        /// return (parsed-bytes (exclude double quote), offset)
        ///
        fn parse_qstr<'a>(
            &self,
            bytes: &'a [u8],
        ) -> Result<(Cow<'a, [u8]>, usize), usize> {
            use State::*;

            let mut state = Start;
            let mut buf = CowBuf::init(bytes);

            #[derive(Clone, Copy)]
            enum State {
                Start,
                InStr,
                OutStr,
                Quoting,
            }

            let mut i = 0;

            while i < bytes.len() {
                let b = bytes[i];

                state = match (state, b) {
                    (Start, DQUOTE) => {
                        buf.start(i + 1);

                        InStr
                    }
                    (
                        InStr,
                        WS![] | 0x21 | 0x23..=0x5b | 0x5d..=0x7e | OBS_TEXT![],
                    ) => {
                        buf.push(b);

                        state
                    }
                    (InStr, BACKSLASH) => Quoting,
                    (Quoting, WS![] | VCHAR![] | OBS_TEXT![]) => {
                        buf.clone_push(b);

                        InStr
                    }
                    (InStr, DQUOTE) => OutStr,
                    _ => break,
                };

                i += 1;
            }

            match state {
                OutStr => Ok((buf.to_cow_slice(), i)),
                _ => Err(i + 1),
            }
        }

        /// return (str, offset)
        fn consume_token<'a>(&self, bytes: &'a [u8]) -> (&'a str, usize) {
            let mut i = 0;

            while i < bytes.len() {
                match bytes[i] {
                    TCHAR![] => (),
                    _ => break,
                }

                i += 1;
            }

            (unsafe { from_utf8_unchecked(&bytes[..i]) }, i)
        }

        fn parse_parameters<'a>(
            &self,
            bytes: &'a [u8],
        ) -> Result<Parameters<'a>, Span> {
            use State::*;

            use super::ParameterValue::*;

            macro_rules! throw {
                ($range:expr) => {
                    Err(Span::from($range))?
                };
            }

            #[derive(Clone, Copy)]
            enum State {
                Start,
                InPreOWS,
                InPostOWS,
            }

            let mut raw_parameters: HashMap<&'a str, Vec<ParameterValue<'a>>> =
                HashMap::new();

            let mut i = 0;
            let mut state = Start;

            while i < bytes.len() {
                state = match (state, bytes[i]) {
                    (Start, WS![]) => {
                        i += 1;

                        InPreOWS
                    },
                    (Start | InPreOWS, b';') => {
                        i += 1;

                        InPostOWS
                    },
                    (InPreOWS | InPostOWS, WS![]) => {
                        i += 1;

                        state
                    },
                    (InPostOWS, TCHAR![]) => {
                        let (param_name, offset) =
                            self.consume_token(&bytes[i..]);
                        i += offset;

                        if i == bytes.len() {
                            throw!(..bytes.len())
                        }

                        let (param_value, offset) = if bytes[i] == DQUOTE {
                            let (qstr, offset) = self
                                .parse_qstr(&bytes[i..])
                                .map_err(|offset| Span::from(i..i + offset))?;

                            (QStr(qstr), offset)
                        }
                        else {
                            let (token, offset) =
                                self.consume_token(&bytes[i..]);

                            (Token(token), offset)
                        };
                        i += offset;

                        match raw_parameters.entry(param_name) {
                            Entry::Occupied(mut occupied) => {
                                occupied.get_mut().push(param_value);
                            }
                            Entry::Vacant(vacant) => {
                                vacant.insert(vec![param_value]);
                            }
                        }

                        InPreOWS
                    }
                    _ => throw!(..=i),
                };
            }

            Ok(Parameters {
                value: raw_parameters,
            })
        }

        fn transmute_field_value_as_singleton<'a>(
            &self,
            value: &'a RawFieldValue<'a>,
        ) -> SingletonFieldValue<'a> {
            use QuotingEnv::*;
            use SingletonFieldValue::*;
            use State::*;

            let mut state = Start;
            let mut buf = CowBuf::init(value);

            #[derive(Clone, Copy)]
            enum State {
                Start,
                InToken,
                InComment(usize),
                InStr,
                OutStr,
                Quoting(QuotingEnv),
                Unknown,
            }

            #[derive(Clone, Copy)]
            enum QuotingEnv {
                Comment(usize),
                Str,
            }

            for (i, b) in value.iter().cloned().enumerate() {
                state = match (state, b) {
                    (Start, TCHAR![]) => {
                        buf.start(i);

                        InToken
                    }
                    (Start, DQUOTE) => {
                        buf.start(i + 1);

                        InStr
                    }
                    (Start, LPAREN) => InComment(1),
                    (InToken, TCHAR![]) => {
                        buf.push(b);

                        state
                    }
                    (
                        InStr,
                        WS![] | 0x21 | 0x23..=0x5b | 0x5d..=0x7e | OBS_TEXT![],
                    ) => {
                        buf.push(b);

                        state
                    }
                    (
                        InComment(..),
                        WS![]
                        | 0x21..=0x27
                        | 0x2A..=0x5B
                        | 0x5D..=0x7E
                        | OBS_TEXT![],
                    ) => state,
                    (InStr | InComment(..), BACKSLASH) => {
                        Quoting(match state {
                            InStr => Str,
                            InComment(cnt) => Comment(cnt),
                            _ => unreachable!(),
                        })
                    }
                    (Quoting(env), WS![] | VCHAR![] | OBS_TEXT![]) => {
                        match env {
                            Str => {
                                buf.clone_push(b);

                                InStr
                            }
                            Comment(cnt) => InComment(cnt),
                        }
                    }
                    (InStr, DQUOTE) => OutStr,
                    (InComment(cnt), RPAREN) => {
                        if cnt > 0 {
                            InComment(cnt - 1)
                        }
                        else {
                            Start
                        }
                    }
                    _ => Unknown,
                }
            }

            match state {
                InToken => Token({
                    match buf.to_cow_slice() {
                        Cow::Borrowed(borrowed) => Cow::Borrowed(unsafe {
                            from_utf8_unchecked(borrowed)
                        }),
                        Cow::Owned(owned) => Cow::Owned(unsafe {
                            String::from_utf8_unchecked(owned)
                        }),
                    }
                }),
                OutStr => QStr(buf.to_cow_slice()),
                _ => Oth(Cow::Borrowed(value)),
            }
        }

        // pub fn transmute_field_value_as_list<'a>(
        //     &self,
        //     value: &'a [RawFieldValue<'a>],
        // ) -> Box<[Member<'a>]> {

        //     let mut members = Vec::with_capacity(value.len());

        //     for raw_field_value in value {
        //         let mut i = 0;

        //         /* try parse token */
        //         while i < raw_field_value.len() {
        //             match raw_field_value[i] {
        //                 TCHAR![] => (),
        //                 b'=' => {
        //                     // parse parameters
        //                 },
        //                 b';' => {
        //                     // parse parameter
        //                 }
        //             }
        //         }
        //     }

        //     members.into_boxed_slice()
        // }

        fn parse_raw_fields<'a>(
            &self,
            bytes: &'a [u8],
        ) -> Result<(RawFields<'a>, usize), ParseError> {
            let mut i = 0;

            macro_rules! throw {
                ($range:expr) => {
                    Err(error!($range))?
                };
            }

            macro_rules! error {
                ($range:expr) => {
                    ParseError {
                        reason: InvalidStartLine,
                        span: ($range).into(),
                    }
                };
            }

            macro_rules! consume {
                ($contpat:pat, $endpat:pat $(,$throw:ident)?) => {{
                    let mut j = i;

                    loop {
                        if j == bytes.len() {
                            throw!(j..j+1)
                        }

                        match bytes[j] {
                            $contpat => (),
                            $endpat => break,
                            $( _ => $throw!(j..j + 1))?
                        }

                        j += 1;
                    }

                    let value = &bytes[i..j];
                    #[allow(unused)]
                    i = j;
                    value
                }};
            }

            macro_rules! FIELD_VCHAR {
                () => {
                    WS![] | VCHAR![] | OBS_TEXT![]
                };
            }

            let mut fields: RawFields = HashMap::new();

            'finish: loop {
                /* parse field name */

                let field_name = unsafe {
                    from_utf8_unchecked(consume!(TCHAR![], b':', throw))
                };

                /* consume `:` */

                i += 1;

                /* consume option white spaces */

                consume!(WS![], _);

                /* parse field value */

                let field_value_start = i;

                let mut field_value =
                    Cow::Borrowed(consume!(FIELD_VCHAR![], CR, throw));

                /* consume option white spaces */

                /* consume CRLF */

                consume!(CR, LF, throw);

                i += 1;

                'nextline: loop {
                    if i == bytes.len() {
                        throw!(i..bytes.len())
                    }

                    match bytes[i] {
                        // obsolete line folding (replace CRLF with SP)
                        SP => {
                            if field_value.is_borrowed() {
                                field_value =
                                    Cow::Owned(field_value.into_owned());
                            }

                            consume!(WS![], _);

                            field_value.to_mut().push(SP);
                            field_value.to_mut().extend(consume!(
                                FIELD_VCHAR![],
                                CR,
                                throw
                            ));

                            consume!(CR, LF, throw);
                        }
                        #[allow(unreachable_patterns)]
                        CR | FIELD_VCHAR![] => {
                            /* push field */

                            let field_value_end = i;

                            let field_value = RawFieldValue {
                                value: field_value,
                                span: (field_value_start..field_value_end)
                                    .into(),
                            };

                            match fields.entry(&field_name) {
                                Entry::Occupied(mut occupied) => {
                                    occupied.get_mut().push(field_value);
                                }
                                Entry::Vacant(vacant) => {
                                    vacant.insert(vec![field_value]);
                                }
                            }

                            if bytes[i] == CR {
                                consume!(CR, LF, throw);
                                break 'finish;
                            }
                            else {
                                break 'nextline;
                            }
                        }
                        _ => throw!(i..i + 1),
                    }
                }
            }

            Ok((fields, i))
        }

        fn lift_fields<'a>(
            &self,
            raw_fields: RawFields<'a>,
        ) -> Result<Fields, ParseError> {
            let mut fields = HashMap::new();

            for (name, value) in raw_fields.into_iter() {}

            Ok(Fields { value: fields })
        }

        fn parse_startline(
            &self,
            bytes: &[u8],
        ) -> Result<(StartLine, usize), ParseError> {
            let mut i = 0;

            macro_rules! throw {
                ($range:expr) => {
                    Err(error!($range))?
                };
            }

            macro_rules! error {
                ($range:expr) => {
                    ParseError {
                        reason: InvalidStartLine,
                        span: ($range).into(),
                    }
                };
            }

            macro_rules! consume {
                (s=$name:literal) => {
                    {
                        let name = $name;
                        consume!(s=name);
                    }
                };
                (s=$name:ident) => {
                    let offset = $name.len();

                    if bytes.len() < i + offset {
                        throw!(i..bytes.len())
                    }

                    if &bytes[i..i + offset] == $name {
                        i += offset;
                    }
                    else {
                        throw!(i..i + offset)
                    }
                };
                ({
                    s=$name:literal => $e:path
                    $(,s=$namex:literal => $ex:path)*
                }
                ) =>
                {{
                    let offset = $name.len();

                    if bytes.len() < i + offset {
                        throw!(i..bytes.len())
                    }

                    if &bytes[i..i + offset] == $name {
                        i += offset;
                        $e
                    }
                    $(else if &bytes[i..i + offset] == $namex {
                        i += offset;
                        $ex
                    })*
                    else {
                        throw!(i..bytes.len())
                    }
                }};
                (c=$char:ident) => {
                    let offset = 1;

                    if bytes.len() < i + offset {
                        throw!(i..bytes.len())
                    }

                    if bytes[i + offset] == $char {
                        i += offset;
                    }
                    else {
                        throw!(i..i + offset)
                    }
                };
                (@$e:ident $offset:expr) => {{
                    let offset = $offset;

                    if bytes.len() < i + offset {
                        throw!(i..bytes.len())
                    }

                    let raw = std::str::from_utf8(&bytes[i..i + offset])
                        .map_err(|_| error!(i..i + offset))?;

                    #[allow(unused)]
                    i += offset;

                    raw.parse::<$e>().map_err(|_| error!(i..i + offset))?
                }};
            }

            macro_rules! offset {
                (=$c:literal) => {{
                    let c = $c;
                    offset!(=c $reason)
                }};
                (=$c:ident) => {{
                    let Some(offset) =
                        bytes[i..].iter().position(|b| *b == $c)
                    else {
                        throw!(i..bytes.len())
                    };

                    offset
                }};
            }

            enum State {
                Start,
                H,
                P,
                Request { method: Method },
                Response { version: Version },
                Finish(StartLine),
            }

            use State::*;

            let mut state = Start;

            while i < bytes.len() {
                state = match (state, bytes[i]) {
                    // status line (response)
                    (Start, b'H') => H,
                    (Start, b'O') => {
                        consume!(s = b"Options");

                        Request {
                            method: Method::Options,
                        }
                    }
                    (Start, b'G') => {
                        consume!(s = b"Get");

                        Request {
                            method: Method::Get,
                        }
                    }
                    (Start, b'P') => {
                        i += 1;

                        P
                    }
                    (Start, b'D') => {
                        consume!(s = b"Delete");

                        Request {
                            method: Method::Delete,
                        }
                    }
                    (H, b'T') => {
                        /* parse status line */

                        consume!(s = b"TTP/");

                        let version = consume!(
                            {
                                s=b"0.9" => Version::HTTP09,
                                s=b"1.0" => Version::HTTP10,
                                s=b"1.1" => Version::HTTP11
                            }
                        );

                        Response { version }
                    }
                    (H, b'e') => {
                        consume!(s = b"ead");

                        Request {
                            method: Method::Head,
                        }
                    }
                    (P, b'o') => {
                        consume!(s = b"ost");

                        Request {
                            method: Method::Post,
                        }
                    }
                    (P, b'u') => {
                        consume!(s = b"ut");

                        Request {
                            method: Method::Put,
                        }
                    }
                    (P, b'a') => {
                        consume!(s = b"atch");

                        Request {
                            method: Method::Patch,
                        }
                    }
                    /* It may allow more lenient parsing that
                    such whitespace includes one or more of the following octets:
                    SP, HTAB, VT (%x0B), FF (%x0C), or bare CR
                    (however it's not recommend) */
                    (Request { method }, SP) => {
                        consume!(c = SP);

                        let target = consume!(@RequestTarget offset!(=SP));

                        consume!(c = SP);

                        let version = consume!(@Version 8);

                        Finish(StartLine::RequestLine {
                            method,
                            target,
                            version,
                        })
                    }
                    (Response { version }, SP) => {
                        consume!(c = SP);

                        let status = consume!(@StatusCode 3);

                        consume!(c = SP);

                        let reason =
                            consume!(@MaybeBoxedStr offset!(=CR)).value;

                        Finish(StartLine::StatusLine {
                            version,
                            status,
                            reason,
                        })
                    }
                    (Finish(startline), ..) => {
                        consume!(s = CRLF);

                        return Ok((startline, i));
                    }
                    _ => throw!(i..i + 1),
                }
            }

            throw!(i..bytes.len())
        }
    }

    impl<'a> Message<'a> {
        pub fn parse(bytes: &'a [u8]) -> Result<Self, ParseError> {
            STANDARD.parse(bytes)
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
            "ABC".to_owned(),
            FieldName::NonSandard("ABC".to_owned().into_boxed_str())
                .to_string()
        );
        assert_eq!(
            "ABC".parse::<FieldName>().unwrap(),
            FieldName::NonSandard("ABC".to_owned().into_boxed_str())
        );
    }
}
