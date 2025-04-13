//! Refrences:
//!
//! 1. [rfc-3986](https://datatracker.ietf.org/doc/html/rfc3986)
//!
//! 1. [rfc-7230](https://datatracker.ietf.org/doc/html/rfc7230)

use std::convert::Infallible;

use nom::{
    AsBytes, AsChar, Compare, FindToken, IResult, Input, Offset, Parser,
    branch::alt,
    bytes::{complete::take_while_m_n, tag},
    character::{
        char,
        complete::{digit0, hex_digit1},
    },
    combinator::{map, map_res, opt, recognize, success},
    error::ParseError,
    multi::{count, many_m_n, many0, many1},
};
use strum::{Display, EnumString};

////////////////////////////////////////////////////////////////////////////////
//// Macros

/// 0..=9
macro_rules! DIGIT {
    () => {
        '0'..='9'
    };
}

macro_rules! ALPHA {
    () => {
        'a'..='z' | 'A'..='Z'
    };
}

macro_rules! HEXDIG {
    () => {
        DIGIT![] | 'A'..='F' | 'a'..='f'
    };
}

macro_rules! UNRESERVED {
    () => {
        ALPHA![] | DIGIT![] | '-' | '.' | '_' | '~'
    };
}

macro_rules! SUB_DELIMS {
    () => {
        '!' | '$' | '&' | '\'' | '(' | ')' | '*' | '+' | ',' | ';' | '='
    };
}

macro_rules! safe_decode {
    ($bytes:expr) => {
        unsafe { std::str::from_utf8_unchecked($bytes) }
    };
}

////////////////////////////////////////////////////////////////////////////////
//// Structures

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
    pub fragment: Option<String>
}


////////////////////////////////////////////////////////////////////////////////
//// Implementations


////////////////////////////////////////////////////////////////////////////////
//// Functions

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
    I: Input + Offset + AsBytes,
    for<'a> I: Compare<&'a str>,
    I::Item: AsChar,
{
    use RequestTarget::*;

    alt((
        map((absolute_path, opt(query)), |(abs_path, query)| Origin {
            abs_path,
            query,
        }),
        map(absolute_uri, |s| Absolute(s)),
        map(authority, |au| Authority(au)),
        map(char('*'), |_| Asterisk),
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
    I: Input + Offset + AsBytes,
    for<'a> I: Compare<&'a str>,
    I::Item: AsChar,
{
    map(recognize(many1((char('/'), segment))), to_string).parse(input)
}

///
/// ```abnf
/// uri = scheme ":" hier-part [ "?" query ] [ "#" fragment ]
/// ```
///
pub fn uri<I>(input: I) -> IResult<I, URI>
where
    I: Input + Offset + AsBytes,
    for<'a> I: Compare<&'a str>,
    I::Item: AsChar,
{
    map((
        scheme,
        char(':'),
        hier_part,
        opt((char('?'), query)),
        opt((char('#'), fragment)),
    ), |(scheme, _, hier_part, opt_q, opt_f)| URI {
        scheme,
        hier_part,
        query: opt_q.map(|(_, q)| q),
        fragment: opt_f.map(|(_, f)| f),
    })
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
    I: Input + Offset + AsBytes,
    for<'a> I: Compare<&'a str>,
    I::Item: AsChar,
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
    I: Input + Offset + AsBytes,
    for<'a> I: Compare<&'a str>,
    I::Item: AsChar,
{
    map(
        (scheme, char(':'), hier_part, opt((char('?'), query))),
        |(scheme, _, hier_part, opt)| AbsoluteURI {
            scheme,
            hier_part,
            query: opt.map(|(_, q)| q),
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
    I: Input + Offset + AsBytes,
    for<'a> I: Compare<&'a str>,
    I::Item: AsChar,
{
    recognize((
        relative_part,
        opt((char('?'), query)),
        opt((char('#'), fragment)),
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
    I: Input + Offset + AsBytes,
    for<'a> I: Compare<&'a str>,
    I::Item: AsChar,
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
    I::Item: AsChar,
{
    let (i, o) =
        recognize((alpha, many0(alt((alpha, digit, take_one_of("+-."))))))
            .parse(input)?;

    // scheme has sentinel for unknown name so parse never fail
    Ok((i, safe_decode!(o.as_bytes()).parse().unwrap()))
}

///
/// ```abnf
/// authority = [ userinfo "@" ] host [ ":" port ]
///
/// ```
///
pub fn authority<I>(input: I) -> IResult<I, Authority>
where
    I: Input + Offset + AsBytes,
    for<'a> I: Compare<&'a str>,
    I::Item: AsChar,
{
    let (input, (userinfo, host, port)) =
        (opt((userinfo, char('@'))), host, opt((char(':'), port)))
            .parse(input)?;

    Ok((
        input,
        Authority {
            userinfo: userinfo
                .map(|(s, _)| safe_decode!(s.as_bytes()).to_owned()),
            host: safe_decode!(host.as_bytes()).to_owned(),
            port: port.map(|(_, p)| p),
        },
    ))
}

///
/// ```abnf
/// authority = [ userinfo "@" ] host [ ":" port ]
///
/// ```
///
pub fn userinfo<I>(input: I) -> IResult<I, I>
where
    I: Input + Offset + AsBytes,
    for<'a> I: Compare<&'a str>,
    I::Item: AsChar,
{
    recognize(many0(alt((
        unreserved,
        pct_encoded,
        sub_delims,
        take_one(':'),
    ))))
    .parse(input)
}

///
/// ```abnf
/// host = IP-literal / IPv4address / reg-name
/// ```
///
pub fn host<I>(input: I) -> IResult<I, I>
where
    I: Input + Offset + AsBytes,
    for<'a> I: Compare<&'a str>,
    I::Item: AsChar,
{
    alt((ip_literal, ipv4address, reg_name)).parse(input)
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
    I: Input + Offset + AsBytes,
    for<'a> I: Compare<&'a str>,
    I::Item: AsChar,
{
    map_res(digit0, |s: I| safe_decode!(s.as_bytes()).parse()).parse(input)
}

///
/// ```abnf
/// IP-literal = "[" ( IPv6address / IPvFuture  ) "]"
/// ```
///
pub fn ip_literal<I>(input: I) -> IResult<I, I>
where
    I: Input + Offset + AsBytes,
    for<'a> I: Compare<&'a str>,
    I::Item: AsChar,
{
    recognize((char('['), alt((ipv6address, ip_vfuture)), char(']')))
        .parse(input)
}

///
/// ```abnf
/// IPvFuture = "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )
/// ```
///
pub fn ip_vfuture<I>(input: I) -> IResult<I, I>
where
    I: Input + Offset + AsBytes,
    I::Item: AsChar,
{
    recognize((
        char('v'),
        hex_digit1,
        char('.'),
        many1((unreserved, sub_delims, char(':'))),
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
    I: Input + Offset + AsBytes,
    for<'a> I: Compare<&'a str>,
    I::Item: AsChar,
{
    recognize(alt((
        recognize((count((h16, char(':')), 6), ones32)),
        recognize((tag("::"), count((h16, char(':')), 5), ones32)),
        recognize((opt(h16), tag("::"), count((h16, char(':')), 4), ones32)),
        recognize((
            opt(many_m_n(0, 1, h16)),
            tag("::"),
            count((h16, char(':')), 3),
            ones32,
        )),
        recognize((
            opt(many_m_n(0, 2, h16)),
            tag("::"),
            count((h16, char(':')), 2),
            ones32,
        )),
        recognize((
            opt(many_m_n(0, 3, h16)),
            tag("::"),
            (h16, char(':')),
            ones32,
        )),
        recognize((opt(many_m_n(0, 4, h16)), tag("::"), ones32)),
        recognize((opt(many_m_n(0, 5, h16)), tag("::"), h16)),
        recognize((opt(many_m_n(0, 6, h16)), tag("::"))),
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
    I: Input + Offset + AsBytes,
    I::Item: AsChar,
{
    // m <= len <= n).
    recognize(take_while_m_n(1, 4, is_hexdig)).parse(input)
}

///
/// ```abnf
/// 1s32 = ( h16 ":" h16 ) / IPv4address
/// ```
///
pub fn ones32<I>(input: I) -> IResult<I, I>
where
    I: Input + Offset + AsBytes,
    for<'a> I: Compare<&'a str>,
    I::Item: AsChar,
{
    // m <= len <= n).
    recognize(alt((recognize((h16, char(':'), h16)), ipv4address)))
        .parse(input)
}

///
/// ```abnf
/// IPv4address   = dec-octet "." dec-octet "." dec-octet "." dec-octet
/// ```
///
pub fn ipv4address<I>(input: I) -> IResult<I, I>
where
    I: Input + Offset + AsBytes,
    for<'a> I: Compare<&'a str>,
    I::Item: AsChar,
{
    // m <= len <= n).
    recognize((
        dec_octet,
        char('.'),
        dec_octet,
        char('.'),
        dec_octet,
        char('.'),
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
    I: Input + Offset + AsBytes,
    for<'a> I: Compare<&'a str>,
    I::Item: AsChar,
{
    // m <= len <= n).
    recognize(alt((
        digit,
        recognize((take_one_of("123456789"), digit)),
        recognize((char('1'), digit, digit)),
        recognize((char('2'), take_one_of("01234"), digit)),
        recognize((tag("25"), take_one_of("012345"))),
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
    I: Input + Offset + AsBytes,
    for<'a> I: Compare<&'a str>,
    I::Item: AsChar,
{
    recognize(many0((unreserved, pct_encoded, sub_delims))).parse(input)
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
    I::Item: AsChar,
{
    map(recognize(many0((char('/'), segment))), to_opt_string).parse(input)
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
    I::Item: AsChar,
{
    map(
        recognize((char('/'), opt((segment_nz, many0((char('/'), segment)))))),
        to_string,
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
    I: Input + Offset + AsBytes,
    I::Item: AsChar,
{
    recognize((segment_nz_nc, many0((char('/'), segment)))).parse(input)
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
    I::Item: AsChar,
{
    map(
        recognize((segment_nz, many0((char('/'), segment)))),
        to_string,
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
    I: Input + Offset + AsBytes,
    I::Item: AsChar,
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
    I: Input + Offset + AsBytes,
    I::Item: AsChar,
{
    recognize(many0(pchar)).parse(input)
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
    I: Input + Offset + AsBytes,
    I::Item: AsChar,
{
    recognize(many1(pchar)).parse(input)
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
    I: Input + Offset + AsBytes,
    I::Item: AsChar,
{
    recognize(many1(alt((
        unreserved,
        pct_encoded,
        sub_delims,
        take_one_of("@"),
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
    I::Item: AsChar,
{
    query(input)
}

///
/// ```abnf
/// query = *( pchar / "/" / "?" )
/// ```
pub fn query<I>(input: I) -> IResult<I, String>
where
    I: Input + Offset + AsBytes,
    I::Item: AsChar,
{
    map(recognize(many0(alt((pchar, take_one_of("/?"))))), to_string)
        .parse(input)
}

/// ```abnf
///   pct-encoded   = "%" HEXDIG HEXDIG
/// ```
pub fn pct_encoded<I>(input: I) -> IResult<I, I>
where
    I: Input + Offset + AsBytes,
    I::Item: AsChar,
{
    recognize((char('%'), take_while_just_n(2, is_hexdig))).parse(input)
}

///
/// ```abnf
/// pchar = unreserved / pct-encoded / sub-delims / ":" / "@"
/// ```
pub fn pchar<I>(input: I) -> IResult<I, I>
where
    I: Input + Offset + AsBytes,
    I::Item: AsChar,
{
    alt((unreserved, pct_encoded, sub_delims, take_one_of(":@"))).parse(input)
}

/// ```abnf
/// unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
/// ```
pub fn unreserved<I>(input: I) -> IResult<I, I>
where
    I: Input + Offset + AsBytes,
    I::Item: AsChar,
{
    take_while_just_n(1, is_unreserved).parse(input)
}

/// ```abnf
/// sub-delims = "!" / "$" / "&" / "'" / "(" / ")"
/// / "*" / "+" / "," / ";" / "="
/// ```
pub fn sub_delims<I>(input: I) -> IResult<I, I>
where
    I: Input + Offset + AsBytes,
    I::Item: AsChar,
{
    take_while_just_n(1, is_sub_delims).parse(input)
}

pub fn alpha<I>(input: I) -> IResult<I, I>
where
    I: Input + Offset + AsBytes,
    I::Item: AsChar,
{
    take_while_just_n(1, is_alpha).parse(input)
}

pub fn digit<I>(input: I) -> IResult<I, I>
where
    I: Input + Offset + AsBytes,
    I::Item: AsChar,
{
    take_while_just_n(1, is_digit).parse(input)
}


////////////////////////////////////////
//// Is Functions

pub fn is_unreserved<Ch: AsChar>(b: Ch) -> bool {
    matches!(b.as_char(), UNRESERVED![])
}

pub fn is_hexdig<Ch: AsChar>(b: Ch) -> bool {
    matches!(b.as_char(), HEXDIG![])
}

pub fn is_sub_delims<Ch: AsChar>(b: Ch) -> bool {
    matches!(b.as_char(), SUB_DELIMS![])
}

pub fn is_alpha<Ch: AsChar>(b: Ch) -> bool {
    matches!(b.as_char(), ALPHA![])
}

pub fn is_digit<Ch: AsChar>(b: Ch) -> bool {
    matches!(b.as_char(), DIGIT![])
}

////////////////////////////////////////
//// Common Functions

pub fn take_while_just_n<F, I, E: ParseError<I>>(
    n: usize,
    cond: F,
) -> impl FnMut(I) -> IResult<I, I, E>
where
    I: Input,
    F: Fn(<I as Input>::Item) -> bool,
{
    take_while_m_n(n, n, cond)
}

pub fn take_one<I, E: ParseError<I>>(
    c: char,
) -> impl Parser<I, Output = I, Error = E>
where
    I: Input + Offset,
    I::Item: AsChar,
{
    recognize(char(c))
}

pub fn take_one_of<I, T, E: ParseError<I>>(
    list: T,
) -> impl FnMut(I) -> IResult<I, I, E>
where
    I: Input,
    I::Item: AsChar,
    T: FindToken<char>,
{
    take_while_just_n(1, move |c: I::Item| list.find_token(c.as_char()))
}

pub fn empty<I>(input: I) -> IResult<I, I>
where
    I: Input + Offset + AsBytes,
    I::Item: AsChar,
{
    recognize(success("")).parse(input)
}


////////////////////////////////////////
//// Helper

fn to_infalliable(_s: &str) -> Infallible {
    unreachable!()
}

pub(crate) fn to_string<I: Input + AsBytes>(input: I) -> String {
    safe_decode!(input.as_bytes()).to_owned()
}

pub(crate) fn to_opt_string<I: Input + AsBytes>(input: I) -> Option<String> {
    let s = to_string(input);

    if s.is_empty() { None } else { Some(s) }
}



#[cfg(test)]
mod tests {
    use m6io::{ByteStr, bstr};
    use nom::{
        Err,
        error::{Error, ErrorKind::*},
    };

    use super::pct_encoded;


    #[test]
    fn test() {
        let bytes: &ByteStr = bstr!("%12%ab%de");

        assert_eq!(pct_encoded(bytes), Ok((bstr!("%ab%de"), bstr!("%12"))));
        assert_eq!(
            pct_encoded(bstr!("%ab%de")),
            Ok((bstr!("%de"), bstr!("%ab")))
        );
        assert_eq!(
            pct_encoded(bstr!("%gh")),
            Err(Err::Error(Error {
                input: bstr!("%gh"),
                code: TakeWhileMN
            }))
        );
    }
}
