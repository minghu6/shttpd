//! Refrences:
//!
//! 1. [rfc-3986](https://datatracker.ietf.org/doc/html/rfc3986)
//!
//! 1. [rfc-7230](https://datatracker.ietf.org/doc/html/rfc7230)

use std::convert::Infallible;

use m6io::{
    ALPHA, DIGIT,
    nom::{
        AsByte,
        byte::{
            alpha, byte, digit, digit1, hexdig, one_of,
            satisfy,
        },
        empty, on_guard_many_m_n, on_guard_many0, on_guard_many1,
        on_guard_opt, safe_as_str_parse, safe_to_opt_string, safe_to_string,
    },
};
use nom::{
    AsBytes, Compare, IResult, Input, Offset, Parser,
    branch::alt,
    bytes::tag,
    combinator::{complete, map, map_res, recognize},
    multi::count,
};
use strum::{Display, EnumString};

////////////////////////////////////////////////////////////////////////////////
//// Macros

macro_rules! UNRESERVED {
    () => {
        ALPHA![] | DIGIT![] | b'-' | b'.' | b'_' | b'~'
    };
}

macro_rules! SUB_DELIMS {
    () => {
        b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'='
    };
}

////////////////////////////////////////////////////////////////////////////////
//// Structures

///
/// There is overlap across four forms
///
/// ```abnf
/// request-target = origin-form
///                / absolute-form
///                / authority-form
///                / asterisk-form
///
/// origin-form    = absolute-path [ "?" query ]
/// absolute-form  = absolute-URI
/// authority-form = authority  (CONNECTION)
/// asterisk-form  = "*"        (OPTIONS)
/// ```
///
#[derive(Debug, Clone)]
pub enum RequestTarget {
    ///
    /// example: GET /where?q=now HTTP/1.1
    ///
    /// absolute path ['?' query]
    ///
    /// When making a request directly to an origin server,
    /// other than a CONNECT or server-wide OPTIONS request (as detailed below)
    Origin {
        /// `absolute-path = 1*( "/" segment )`
        abs_path: String,
        query: Option<String>,
    },
    /// absolute uri
    ///
    /// When making a request to a proxy,
    /// other than a CONNECT or server-wide OPTIONS request (as detailed below)
    Absolute(AbsoluteURI),
    ///
    ///
    /// CONNECT www.example.com:80 HTTP/1.1
    ///
    Authority(Authority),
    /// example: OPTIONS * HTTP/1.1
    ///
    /// is only used for a server-wide OPTIONS request
    Asterisk,
}

///
/// ```abnf
/// absolute-URI  = scheme ":" hier-part [ "?" query ]
/// ```
#[derive(Debug, Clone)]
pub struct AbsoluteURI {
    pub scheme: Scheme,
    pub hier_part: HierPart,
    pub query: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Authority {
    pub userinfo: Option<String>,
    pub host: String,
    pub port: Option<u16>,
}

///
/// reference: [urt-schemes](https://www.iana.org/assignments/uri-schemes/uri-schemes.xhtml)
///
#[derive(EnumString, Display, Clone, Debug)]
#[strum(
    ascii_case_insensitive,
    parse_err_fn = to_infalliable,
    parse_err_ty = Infallible
)]
pub enum Scheme {
    HTTP,
    HTTPS,
    /// Used to create email links (e.g., mailto:example@example.com)
    Mailto,
    File,
    FTP,
    FTPS,
    Data,
    Telnet,
    /// Lightweight Directory Access Protocol
    LDAP,
    /// Real-Time Streaming Protocol
    RTSP,
    /// Session Initiation Protocol (used for initiating communication sessions)
    SIP,
    /// `smb`: Server Message Block (used for sharing files and printers)
    SMB,
    /// WebSocket
    WS,
    /// Secure WebSocket
    WSS,
    /// Internet Relay Chat
    IRC,
    /// Used for referencing resources in peer-to-peer networks
    Magnet,
    #[strum(serialize = "{0}", default)]
    Oth(String),
}

#[derive(Debug, Clone)]
///
/// Hierarchical Part
pub enum HierPart {
    AuthorityAbEmpPath {
        authority: Authority,
        rel_path: Option<String>,
    },
    AbsPath(String),
    RelPath(String),
    EmpPath,
}

///
/// ```abnf
/// uri = scheme ":" hier-part [ "?" query ] [ "#" fragment ]
/// ```
#[derive(Debug, Clone)]
pub struct URI {
    pub scheme: Scheme,
    pub hier_part: HierPart,
    pub query: Option<String>,
    pub fragment: Option<String>,
}


////////////////////////////////////////////////////////////////////////////////
//// Implementations

impl RequestTarget {
    pub fn path(&self) -> Option<&str> {
        use RequestTarget::*;

        match self {
            Origin { abs_path, .. } => Some(abs_path),
            Absolute(absolute_uri) => absolute_uri.path(),
            Authority { .. } | Asterisk => None,
        }
    }

    pub fn query(&self) -> Option<&str> {
        use RequestTarget::*;

        match self {
            Origin { query, .. } => query.as_deref(),
            Absolute(absolute_uri) => absolute_uri.query(),
            Authority { .. } | Asterisk => None,
        }
    }
}

impl AbsoluteURI {
    pub fn path(&self) -> Option<&str> {
        self.hier_part.path()
    }

    pub fn query(&self) -> Option<&str> {
        self.query.as_deref()
    }
}

impl HierPart {
    pub fn path(&self) -> Option<&str> {
        use HierPart::*;

        match self {
            AuthorityAbEmpPath { rel_path, .. } => rel_path.as_deref(),
            AbsPath(abs_path) => Some(abs_path),
            RelPath(rel_path) => Some(rel_path),
            EmpPath => None,
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
//// Functions

///
/// There is overlap across four forms
///
/// ```abnf
/// request-target = origin-form
///                / absolute-form
///                / authority-form
///                / asterisk-form
///
/// origin-form    = absolute-path [ "?" query ]
/// absolute-form  = absolute-URI
/// authority-form = authority
/// asterisk-form  = "*"
/// ```
///
pub fn request_target<I>(input: I) -> IResult<I, RequestTarget>
where
    I: Input + Offset + AsBytes + Compare<&'static str>,
    I::Item: AsByte,
{
    use RequestTarget::*;

    alt((
        map(byte(b'*'), |_| Asterisk),
        map((absolute_path, on_guard_opt(query)), |(abs_path, query)| {
            Origin { abs_path, query }
        }),
        // complete distinguish
        complete(map(absolute_uri, |s| Absolute(s))),
        map(authority, |au| Authority(au)),
    ))
    .parse(input)
}

///
/// ```abnf
/// absolute-path = 1*( "/" segment )
/// ```
///
pub fn absolute_path<I>(input: I) -> IResult<I, String>
where
    I: Input + Offset + AsBytes + Compare<&'static str>,
    I::Item: AsByte,
{
    map(
        recognize(on_guard_many1((byte(b'/'), segment))),
        safe_to_string,
    )
    .parse(input)
}

///
/// ```abnf
/// uri = scheme ":" hier-part [ "?" query ] [ "#" fragment ]
/// ```
///
pub fn uri<I>(input: I) -> IResult<I, URI>
where
    I: Input + Offset + AsBytes + Compare<&'static str>,
    I::Item: AsByte,
{
    map(
        (
            scheme,
            byte(b':'),
            hier_part,
            on_guard_opt((byte(b'?'), query)),
            on_guard_opt((byte(b'#'), fragment)),
        ),
        |(scheme, _, hier_part, opt_q, opt_f)| URI {
            scheme,
            hier_part,
            query: opt_q.map(|(_, q)| q),
            fragment: opt_f.map(|(_, f)| f),
        },
    )
    .parse(input)
}

///
/// Hierarchical Part
///
/// ```abnf
/// hier-part = "//" authority path-abempty
///           / path-absolute
///           / path-rootless
///           / path-empty
/// ```
///
pub fn hier_part<I>(input: I) -> IResult<I, HierPart>
where
    I: Input + Offset + AsBytes + Compare<&'static str>,
    I::Item: AsByte,
{
    use HierPart::*;

    alt((
        // "//" authority path-abempty
        map(
            (tag("//"), authority::<I>, path_abempty),
            |(_, authority, rel_path)| AuthorityAbEmpPath {
                authority,
                rel_path,
            },
        ),
        // path_absolute,
        map(path_absolute, |s| AbsPath(s)),
        // path_rootless,
        map(path_rootless, |s| RelPath(s)),
        // path_empty,
        map(path_empty, |_| EmpPath),
    ))
    .parse(input)
}

///
/// ```abnf
/// absolute-URI  = scheme ":" hier-part [ "?" query ]
/// ```
///
pub fn absolute_uri<I>(input: I) -> IResult<I, AbsoluteURI>
where
    I: Input + Offset + AsBytes + Compare<&'static str>,
    I::Item: AsByte,
{
    map(
        (
            scheme,
            byte(b':'),
            hier_part,
            on_guard_opt((byte(b'?'), query)),
        ),
        |(scheme, _, hier_part, opt_q)| AbsoluteURI {
            scheme,
            hier_part,
            query: opt_q.map(|(_, q)| q),
        },
    )
    .parse(input)
}

///
/// ```abnf
/// relative-ref = relative-part [ "?" query ] [ "#" fragment ]
/// ```
///
pub fn relative_ref<I>(input: I) -> IResult<I, I>
where
    I: Input + Offset + AsBytes + Compare<&'static str>,
    I::Item: AsByte,
{
    recognize((
        relative_part,
        on_guard_opt((byte(b'?'), query)),
        on_guard_opt((byte(b'#'), fragment)),
    ))
    .parse(input)
}

///
/// ```abnf
/// relative-part = "//" authority path-abempty
///               / path-absolute
///               / path-noscheme
///               / path-empty
/// ```
///
pub fn relative_part<I>(input: I) -> IResult<I, I>
where
    I: Input + Offset + AsBytes + Compare<&'static str>,
    I::Item: AsByte,
{
    alt((
        recognize((tag("//"), authority, path_abempty)),
        recognize(path_absolute),
        path_noscheme,
        path_empty,
    ))
    .parse(input)
}

///
/// ```abnf
/// scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
/// ```
///
pub fn scheme<I>(input: I) -> IResult<I, Scheme>
where
    I: Input + Offset + AsBytes,
    I::Item: AsByte,
{
    map(
        recognize((
            alpha,
            on_guard_many0(alt((alpha, digit, one_of("+-.")))),
        )),
        // scheme has sentinel for unknown name so parse never fail
        |s| safe_as_str_parse(s).unwrap(),
    )
    .parse(input)
}

///
/// ```abnf
/// authority = [ userinfo "@" ] host [ ":" port ]
///
/// ```
///
pub fn authority<I>(input: I) -> IResult<I, Authority>
where
    I: Input + Offset + AsBytes + Compare<&'static str>,
    I::Item: AsByte,
{
    map(
        (
            on_guard_opt(complete((userinfo::<I>, byte(b'@')))),
            host,
            on_guard_opt(complete((byte(b':'), port))),
        ),
        |(userinfo, host, port)| Authority {
            userinfo: userinfo.map(|(s, _)| safe_to_string(s)),
            host,
            port: port.map(|(_, p)| p),
        },
    )
    .parse(input)
}

///
/// ```abnf
/// userinfo = *( unreserved / pct-encoded / sub-delims / ":" )
/// ```
///
pub fn userinfo<I>(input: I) -> IResult<I, I>
where
    I: Input + Offset + Compare<&'static str>,
    I::Item: AsByte,
{
    recognize(on_guard_many0(alt((
        unreserved,
        pct_encoded,
        sub_delims,
        recognize(byte(b':')),
    ))))
    .parse(input)
}

///
/// ```abnf
/// host = IP-literal / IPv4address / reg-name
/// ```
///
pub fn host<I>(input: I) -> IResult<I, String>
where
    I: Input + Offset + AsBytes + Compare<&'static str>,
    I::Item: AsByte,
{
    map(alt((ip_literal, ipv4address, reg_name)), safe_to_string).parse(input)
}

///
/// ```abnf
/// port = *DIGIT
/// ```
/// the ABNF definition says that the port is optional,
///
/// but specifying an empty port is not standard and may not be supported by all URI parsers.
///
pub fn port<I>(input: I) -> IResult<I, u16>
where
    I: Input + Offset + AsBytes + Compare<&'static str>,
    I::Item: AsByte,
{
    map_res(digit1, |s: I| safe_as_str_parse(s)).parse(input)
}

///
/// ```abnf
/// IP-literal = "[" ( IPv6address / IPvFuture  ) "]"
/// ```
///
pub fn ip_literal<I>(input: I) -> IResult<I, I>
where
    I: Input + Offset + Compare<&'static str>,
    I::Item: AsByte,
{
    recognize((byte(b'['), alt((ipv6address, ip_vfuture)), byte(b']')))
        .parse(input)
}

///
/// ```abnf
/// IPvFuture = "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )
/// ```
///
pub fn ip_vfuture<I>(input: I) -> IResult<I, I>
where
    I: Input + Offset,
    I::Item: AsByte,
{
    recognize((
        byte(b'v'),
        on_guard_many1(hexdig),
        byte(b'.'),
        on_guard_many1((unreserved, sub_delims, byte(b':'))),
    ))
    .parse(input)
}

///
/// ```abnf
///    IPv6address =             6( h16 ":" ) ls32
/// /                       "::" 5( h16 ":" ) ls32
/// / [               h16 ] "::" 4( h16 ":" ) ls32
/// / [ *1( h16 ":" ) h16 ] "::" 3( h16 ":" ) ls32
/// / [ *2( h16 ":" ) h16 ] "::" 2( h16 ":" ) ls32
/// / [ *3( h16 ":" ) h16 ] "::"    h16 ":"   ls32
/// / [ *4( h16 ":" ) h16 ] "::"              ls32
/// / [ *5( h16 ":" ) h16 ] "::"              h16
/// / [ *6( h16 ":" ) h16 ] "::"
/// ```
///
pub fn ipv6address<I>(input: I) -> IResult<I, I>
where
    I: Input + Offset + Compare<&'static str>,
    I::Item: AsByte,
{
    recognize(alt((
        recognize((count((h16, byte(b':')), 6), ones32)),
        recognize((tag("::"), count((h16, byte(b':')), 5), ones32)),
        recognize((
            on_guard_opt(h16),
            tag("::"),
            count((h16, byte(b':')), 4),
            ones32,
        )),
        recognize((
            on_guard_opt(on_guard_many_m_n(0, 1, h16)),
            tag("::"),
            count((h16, byte(b':')), 3),
            ones32,
        )),
        recognize((
            on_guard_opt(on_guard_many_m_n(0, 2, h16)),
            tag("::"),
            count((h16, byte(b':')), 2),
            ones32,
        )),
        recognize((
            on_guard_opt(on_guard_many_m_n(0, 3, h16)),
            tag("::"),
            (h16, byte(b':')),
            ones32,
        )),
        recognize((
            on_guard_opt(on_guard_many_m_n(0, 4, h16)),
            tag("::"),
            ones32,
        )),
        recognize((
            on_guard_opt(on_guard_many_m_n(0, 5, h16)),
            tag("::"),
            h16,
        )),
        recognize((on_guard_opt(on_guard_many_m_n(0, 6, h16)), tag("::"))),
    )))
    .parse(input)
}

///
/// ```abnf
/// h16 = 1*4HEXDIG
/// ```
///
pub fn h16<I>(input: I) -> IResult<I, I>
where
    I: Input + Offset,
    I::Item: AsByte,
{
    // m <= len <= n).
    recognize(on_guard_many_m_n(1, 4, hexdig)).parse(input)
}

///
/// ```abnf
/// 1s32 = ( h16 ":" h16 ) / IPv4address
/// ```
///
pub fn ones32<I>(input: I) -> IResult<I, I>
where
    I: Input + Offset + Compare<&'static str>,
    I::Item: AsByte,
{
    // m <= len <= n).
    recognize(alt((recognize((h16, byte(b':'), h16)), ipv4address)))
        .parse(input)
}

///
/// ```abnf
/// IPv4address   = dec-octet "." dec-octet "." dec-octet "." dec-octet
/// ```
///
pub fn ipv4address<I>(input: I) -> IResult<I, I>
where
    I: Input + Offset + Compare<&'static str>,
    I::Item: AsByte,
{
    // m <= len <= n).
    recognize((
        dec_octet,
        byte(b'.'),
        dec_octet,
        byte(b'.'),
        dec_octet,
        byte(b'.'),
        dec_octet,
    ))
    .parse(input)
}

///
/// decimal octet (eight bit group)
///
/// ```abnf
/// dec-octet = DIGIT                 ; 0-9
///           / %x31-39 DIGIT         ; 10-99
///           / "1" 2DIGIT            ; 100-199
///           / "2" %x30-34 DIGIT     ; 200-249
///           / "25" %x30-35          ; 250-255
/// ```
///
pub fn dec_octet<I>(input: I) -> IResult<I, I>
where
    I: Input + Offset + Compare<&'static str>,
    I::Item: AsByte,
{
    // m <= len <= n).
    recognize(alt((
        recognize(digit),
        recognize((one_of("123456789"), digit)),
        recognize((byte(b'1'), digit, digit)),
        recognize((byte(b'2'), one_of("01234"), digit)),
        recognize((tag("25"), one_of("012345"))),
    )))
    .parse(input)
}

///
/// registered name
///
/// ```abnf
/// reg-name = *( unreserved / pct-encoded / sub-delims )
/// ```
///
pub fn reg_name<I>(input: I) -> IResult<I, I>
where
    I: Input + Offset + Compare<&'static str>,
    I::Item: AsByte,
{
    recognize(on_guard_many0(alt((unreserved, pct_encoded, sub_delims))))
        .parse(input)
}

///
/// begins with "/" or is empty
///
/// `ab` = path absolute: `/`
///
/// `empty` = whole empty: 0<pchar>
///
///
/// ```abnf
/// path-abempty = *( "/" segment )
/// ```
///
pub fn path_abempty<I>(input: I) -> IResult<I, Option<String>>
where
    I: Input + Offset + AsBytes,
    I::Item: AsByte,
{
    map(
        recognize(on_guard_many0((byte(b'/'), segment))),
        safe_to_opt_string,
    )
    .parse(input)
}

///
/// begins with "/" but not "//"
///
/// ```abnf
/// path-absolute = "/" [ segment-nz *( "/" segment ) ]
/// ```
///
pub fn path_absolute<I>(input: I) -> IResult<I, String>
where
    I: Input + Offset + AsBytes,
    I::Item: AsByte,
{
    map(
        recognize((
            byte(b'/'),
            on_guard_opt((segment_nz, on_guard_many0((byte(b'/'), segment)))),
        )),
        safe_to_string,
    )
    .parse(input)
}

///
/// begins with a non-colon segment
///
/// ```abnf
/// path-noscheme = segment-nz-nc *( "/" segment )
/// ```
///
pub fn path_noscheme<I>(input: I) -> IResult<I, I>
where
    I: Input + Offset,
    I::Item: AsByte,
{
    recognize((segment_nz_nc, on_guard_many0((byte(b'/'), segment))))
        .parse(input)
}

///
/// begins with a segment
///
/// ```abnf
/// path-rootless = segment-nz *( "/" segment )
/// ```
///
pub fn path_rootless<I>(input: I) -> IResult<I, String>
where
    I: Input + Offset + AsBytes,
    I::Item: AsByte,
{
    map(
        recognize((segment_nz, on_guard_many0((byte(b'/'), segment)))),
        safe_to_string,
    )
    .parse(input)
}

///
/// zero characters
///to
/// ```abnf
/// path-empty = 0<pchar>
/// ```
///
pub fn path_empty<I>(input: I) -> IResult<I, I>
where
    I: Input + Offset,
{
    empty(input)
}

///
/// segment
///
/// ```abnf
/// segment = *pchar
/// ```
///
pub fn segment<I>(input: I) -> IResult<I, I>
where
    I: Input + Offset,
    I::Item: AsByte,
{
    recognize(on_guard_many0(pchar)).parse(input)
}

///
/// segment non-zero
///
/// ```abnf
/// segment-nz = 1*pchar
/// ```
///
pub fn segment_nz<I>(input: I) -> IResult<I, I>
where
    I: Input + Offset,
    I::Item: AsByte,
{
    recognize(on_guard_many1(pchar)).parse(input)
}

///
/// segment non-zero no-colon
///
/// ```abnf
/// segment-nz-nc = 1*( unreserved / pct-encoded / sub-delims / "@" )
/// ```
///
pub fn segment_nz_nc<I>(input: I) -> IResult<I, I>
where
    I: Input + Offset,
    I::Item: AsByte,
{
    recognize(on_guard_many1(alt((
        unreserved,
        pct_encoded,
        sub_delims,
        recognize(one_of("@")),
    ))))
    .parse(input)
}

///
/// ```abnf
/// fragment = *( pchar / "/" / "?" )
/// ```
pub fn fragment<I>(input: I) -> IResult<I, String>
where
    I: Input + Offset + AsBytes,
    I::Item: AsByte,
{
    query(input)
}

///
/// ```abnf
/// query = *( pchar / "/" / "?" )
/// ```
///
/// actually no empty
///
pub fn query<I>(input: I) -> IResult<I, String>
where
    I: Input + Offset + AsBytes,
    I::Item: AsByte,
{
    map(
        recognize(on_guard_many1(alt((pchar, recognize(one_of("/?")))))),
        safe_to_string,
    )
    .parse(input)
}

/// ```abnf
/// pct-encoded = "%" HEXDIG HEXDIG
/// ```
pub fn pct_encoded<I>(input: I) -> IResult<I, I>
where
    I: Input + Offset,
    I::Item: AsByte,
{
    recognize((byte(b'%'), hexdig, hexdig)).parse(input)
}

///
/// ```abnf
/// pchar = unreserved / pct-encoded / sub-delims / ":" / "@"
/// ```
pub fn pchar<I>(input: I) -> IResult<I, I>
where
    I: Input + Offset,
    I::Item: AsByte,
{
    alt((
        unreserved,
        pct_encoded,
        sub_delims,
        recognize(one_of(*b":@")),
    ))
    .parse(input)
}

/// ```abnf
/// unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
/// ```
pub fn unreserved<I>(input: I) -> IResult<I, I>
where
    I: Input + Offset,
    I::Item: AsByte,
{
    recognize(satisfy(is_unreserved)).parse(input)
}

/// ```abnf
/// sub-delims = "!" / "$" / "&" / "'" / "(" / ")"
/// / "*" / "+" / "," / ";" / "="
/// ```
pub fn sub_delims<I>(input: I) -> IResult<I, I>
where
    I: Input + Offset,
    I::Item: AsByte,
{
    recognize(satisfy(is_sub_delims)).parse(input)
}

pub fn is_unreserved<T: AsByte>(b: T) -> bool {
    matches!(b.as_byte(), UNRESERVED![])
}

pub fn is_sub_delims<T: AsByte>(b: T) -> bool {
    matches!(b.as_byte(), SUB_DELIMS![])
}

////////////////////////////////////////
//// Helper

#[allow(unused)]
pub(crate) fn to_infalliable(_s: &str) -> Infallible {
    unreachable!()
}


#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use m6io::{ByteStr, bstr};
    use nom::{
        Err,
        error::{Error, ErrorKind::*},
    };

    use super::*;

    #[test]
    fn verify_usage() {
        let bytes: &ByteStr = bstr!("%12%ab%de");

        assert_eq!(pct_encoded(bytes), Ok((bstr!("%ab%de"), bstr!("%12"))));
        assert_eq!(
            pct_encoded(bstr!("%ab%de")),
            Ok((bstr!("%de"), bstr!("%ab")))
        );
        assert_eq!(
            pct_encoded(bstr!("%gh")),
            Err(Err::Error(Error {
                input: bstr!("gh"),
                code: Satisfy
            }))
        );
    }

    #[test]
    fn test_path() {
        pchar("a").unwrap();
        pchar("@").unwrap();

        // matches!(hexdig(""), Err(Err::Incomplete(..)));
        // matches!(pchar(""), Err(Err::Incomplete(..)));

        on_guard_many0(pchar).parse("abc").unwrap();

        segment("abc").unwrap();
        (byte(b'/'), segment).parse("/abc").unwrap();

        reg_name("abc").unwrap();

        absolute_path("/a").unwrap();
        absolute_path("/").unwrap();

        host("www.baidu.com").unwrap();
        authority("www.baidu.com").unwrap();

        Scheme::from_str("www").unwrap();

        println!("{:?}", request_target("/abc/def").unwrap());
        println!("{:?}", request_target("www.baidu.com").unwrap());
        println!("{:?}", request_target("http://www.baidu.com:234").unwrap());
        println!("{:?}", request_target("*").unwrap());

        println!("{:?}", on_guard_opt(query).parse(""));

        println!("{:#?}", request_target("/").unwrap());
    }
}
