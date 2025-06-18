//! Refer:
//!
//! 1. [RFC-5234 - Augmented BNF for Syntax Specifications: ABNF](https://datatracker.ietf.org/doc/html/rfc5234)
//!
//! 1. [RFC-9110 - HTTP Semantics](https://datatracker.ietf.org/doc/html/rfc9110)
//!
//! 1. [RFC-9112 - HTTP/1.1](https://datatracker.ietf.org/doc/html/rfc9112)
///
use std::{
    ascii::Char::*,
    collections::{HashMap, hash_map::Entry},
    convert::Infallible,
    ops::Deref,
    str::FromStr,
};

use m6io::{
    ALPHA, DIGIT, WS,
    bstr::{ByteStr, ConsumeByteStr, FromByteStr},
    cow::FlatCow,
    nom::{
        AsByte,
        byte::{
            byte, crlf, digit1, digit1_as_u64, hexdig1, is_digit, safe_as_str,
            safe_as_str_parse, safe_to_string, satisfy, sp, ws,
        },
        combinator::{
            empty, on_guard_fold_many0, on_guard_fold_many1, on_guard_many0,
            on_guard_many1, on_guard_opt,
        },
    },
};
use nom::{
    AsBytes, Compare, Err, IResult, Input, Offset, Parser,
    branch::alt,
    bytes::{tag, tag_no_case, take_while_m_n},
    combinator::{map, map_res, opt, recognize, value, verify},
    error::Error,
    sequence::{delimited, preceded, separated_pair, terminated},
};
use nonempty::NonEmpty;
use strum::IntoEnumIterator;

use super::{
    uri::{host as uri_host, port, request_target},
    *,
};
use crate::application::mime::{
    ApplicationType, MediaTopType, MessageType, MultipartType, TextType,
};

////////////////////////////////////////////////////////////////////////////////
//// Macros

/// VCHAR exclude delimiters `"(),/:;<=>?@[\]{}"`
macro_rules! TCHAR {
    () => {
        b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' |
        b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~' |
        DIGIT![] | ALPHA![]
    };
}

macro_rules! FIELD_VCHAR {
    () => {
        WS![] | VCHAR![] | OBS_TEXT![]
    };
}

/// visable ascii char
macro_rules! VCHAR {
    () => {
        0x21..=0x7E
    };
}

/// obs-text, obsoleted chars, viewed as opaque data
macro_rules! OBS_TEXT {
    () => {
        0x80..=0xFF
    };
}

///
/// ```abnf
/// qdtext = HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text
/// ```
///
macro_rules! QDTEXT {
    () => {
        WS![] | 0x21 | 0x23..=0x5b | 0x5d..=0x7e | OBS_TEXT![]
    };
}

/// WS + VCHAR + OBS_TEXT - '('(28) ')'(29) '/'(5C)
macro_rules! CTEXT {
    () => {
        WS![]
        | 0x21..=0x27
        | 0x2A..=0x5B
        | 0x5D..=0x7E
        | OBS_TEXT![]
    };
}

/// VCHAR except double quotes, plus obs-text
macro_rules! ETAGC {
    () => {
        0x21 | 0x23..=0x7E | OBS_TEXT![]
    };
}

////////////////////////////////////////////////////////////////////////////////
//// Constants

const HTAB: u8 = CharacterTabulation.to_u8();
const SP: u8 = Space.to_u8();
const LPAREN: u8 = LeftParenthesis.to_u8();
const RPAREN: u8 = RightParenthesis.to_u8();


trait LiftFieldValue<'a>: Sized {
    fn lift(
        raw_field_values: NonEmpty<RawFieldValue<'a>>,
    ) -> RawParseResult<Self>;
}

////////////////////////////////////////////////////////////////////////////////
//// Structures

pub type RawFields<'a> = HashMap<FieldName, NonEmpty<RawFieldValue<'a>>>;

#[derive(Deref)]
#[deref(forward)]
pub struct RawFieldValue<'a> {
    value: FlatCow<'a, ByteStr>,
}

type RawParseResult<T> = Result<T, ByteString>;

#[derive(Debug)]
pub struct ParseError {
    pub input: ByteString,
    pub kind: ParseErrorKind,
}

#[derive(Debug)]
pub enum ParseErrorKind {
    StartLine,
    Fields,
    Field(FieldName),
}

////////////////////////////////////////
//// Inner Structures


////////////////////////////////////////////////////////////////////////////////
//// Implementations

impl Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:#?}")
    }
}

impl<'a> Debug for RawFieldValue<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.value.decode_as_utf8() {
            Ok(s) => write!(f, "{s}"),
            Err(_) => write!(f, "[non-utf8-compatiable-data]"),
        }
    }
}

impl<'a> LiftFieldValue<'a> for AcceptEncoding {
    fn lift(
        raw_field_values: NonEmpty<RawFieldValue<'a>>,
    ) -> RawParseResult<Self> {
        fold_map_parser_field_list(
            &field_list_based(&raw_field_values)?,
            (codings, on_guard_opt(weight)),
            |values| Self { values },
        )
    }
}

impl<'a> LiftFieldValue<'a> for TransferEncoding {
    fn lift(
        raw_field_values: NonEmpty<RawFieldValue<'a>>,
    ) -> RawParseResult<Self> {
        fold_map_parser_field_list(
            &field_list_based(&raw_field_values)?,
            transfer_coding,
            |value| TransferEncoding { value },
        )
    }
}

impl<'a> LiftFieldValue<'a> for Host {
    fn lift(
        raw_field_values: NonEmpty<RawFieldValue<'a>>,
    ) -> RawParseResult<Self> {
        map_parser_singleton(&raw_field_values, host)
    }
}

impl<'a> LiftFieldValue<'a> for AcceptCharset {
    fn lift(
        raw_field_values: NonEmpty<RawFieldValue<'a>>,
    ) -> RawParseResult<Self> {
        fold_map_parser_field_list(
            &field_list_based(&raw_field_values)?,
            (charset, on_guard_opt(weight)),
            |values| Self { values },
        )
    }
}

impl<'a> LiftFieldValue<'a> for Accept {
    fn lift(
        raw_field_values: NonEmpty<RawFieldValue<'a>>,
    ) -> RawParseResult<Self> {
        fold_map_parser_field_list(
            &field_list_based(&raw_field_values)?,
            (media_range, on_guard_opt(weight)),
            |values| Self { values },
        )
    }
}

impl<'a> LiftFieldValue<'a> for Connection {
    fn lift(
        raw_field_values: NonEmpty<RawFieldValue<'a>>,
    ) -> RawParseResult<Self> {
        fold_map_res_field_list(
            &field_list_based(&raw_field_values)?,
            |v| safe_as_str_parse(v.deref()),
            |value| Connection { value },
        )
    }
}

impl<'a> LiftFieldValue<'a> for Date {
    fn lift(
        raw_field_values: NonEmpty<RawFieldValue<'a>>,
    ) -> RawParseResult<Self> {
        map_res_singleton(&raw_field_values, |s| s.deref().parse())
    }
}

impl<'a> LiftFieldValue<'a> for IfMatch {
    fn lift(
        raw_field_values: NonEmpty<RawFieldValue<'a>>,
    ) -> RawParseResult<Self> {
        let mut vec = Vec::new();

        for value in raw_field_values {
            let (_, it) = if_match(value.deref())
                .map_err(|_err| value.deref().to_owned())?;

            match it {
                IfMatch::Star => return Ok(it),
                IfMatch::List(entity_tags) => vec.extend(entity_tags),
            }
        }

        Ok(IfMatch::List(vec))
    }
}

impl<'a> LiftFieldValue<'a> for IfRange {
    fn lift(
        raw_field_values: NonEmpty<RawFieldValue<'a>>,
    ) -> RawParseResult<Self> {
        map_res_singleton(&raw_field_values, |s| s.deref().parse())
    }
}

impl<'a> LiftFieldValue<'a> for RangesSpecifier {
    fn lift(
        raw_field_values: NonEmpty<RawFieldValue<'a>>,
    ) -> RawParseResult<Self> {
        map_parser_singleton(&raw_field_values, ranges_specifier)
    }
}

impl<'a> LiftFieldValue<'a> for ContentRange {
    fn lift(
        raw_field_values: NonEmpty<RawFieldValue<'a>>,
    ) -> RawParseResult<Self> {
        map_parser_singleton(&raw_field_values, content_range)
    }
}

impl<'a> LiftFieldValue<'a> for AcceptRanges {
    fn lift(
        raw_field_values: NonEmpty<RawFieldValue<'a>>,
    ) -> RawParseResult<Self> {
        map_parser_singleton(&raw_field_values, accecpt_ranges)
    }
}

impl<'a> LiftFieldValue<'a> for MediaType {
    fn lift(
        raw_field_values: NonEmpty<RawFieldValue<'a>>,
    ) -> RawParseResult<Self> {
        map_parser_singleton(&raw_field_values, media_type)
    }
}

impl<'a> LiftFieldValue<'a> for Server {
    fn lift(
        raw_field_values: NonEmpty<RawFieldValue<'a>>,
    ) -> RawParseResult<Self> {
        map_res_singleton(&raw_field_values, |raw| {
            let (it, _i) = Server::consume_bstr(raw.deref())
                .map_err(|_| raw.deref().to_owned())?;

            Ok::<_, ByteString>(it)
        })
    }
}

impl<'a> LiftFieldValue<'a> for UserAgent {
    fn lift(
        raw_field_values: NonEmpty<RawFieldValue<'a>>,
    ) -> RawParseResult<Self> {
        map_res_singleton(&raw_field_values, |raw| {
            let (it, _i) = UserAgent::consume_bstr(raw.deref())
                .map_err(|_| raw.deref().to_owned())?;

            Ok::<_, ByteString>(it)
        })
    }
}

///
/// ```abnf
/// *( field-line CRLF )
/// ```
///
impl FromByteStr for Fields {
    type Err = ParseError;

    fn from_bstr(bytes: &ByteStr) -> Result<Self, Self::Err> {
        fn lift_fields(
            raw_fields: RawFields,
        ) -> Result<Fields, (ByteString, FieldName)> {
            let mut fields = Vec::new();

            for (field_name, field_values) in raw_fields.into_iter() {
                let field_value = match &field_name {
                    FieldName::Accept => Field::Accept(
                        Accept::lift(field_values)
                            .map_err(|err| (err, field_name))?,
                    ),
                    FieldName::AcceptEncoding => Field::AcceptEncoding(
                        AcceptEncoding::lift(field_values)
                            .map_err(|err| (err, field_name))?,
                    ),
                    FieldName::TransferEncoding => Field::TransferEncoding(
                        TransferEncoding::lift(field_values)
                            .map_err(|err| (err, field_name))?,
                    ),
                    FieldName::Connection => Field::Connection(
                        Connection::lift(field_values)
                            .map_err(|err| (err, field_name))?,
                    ),
                    FieldName::ContentType => Field::ContentType(
                        ContentType::lift(field_values)
                            .map_err(|err| (err, field_name))?,
                    ),
                    FieldName::Date => Field::Date(
                        HTTPDate::lift(field_values)
                            .map_err(|err| (err, field_name))?,
                    ),
                    FieldName::Host => Field::Host(
                        Host::lift(field_values)
                            .map_err(|err| (err, field_name))?,
                    ),
                    FieldName::IfMatch => Field::IfMatch(
                        IfMatch::lift(field_values)
                            .map_err(|err| (err, field_name))?,
                    ),
                    FieldName::IfNoneMatch => Field::IfNoneMatch(
                        IfMatch::lift(field_values)
                            .map_err(|err| (err, field_name))?,
                    ),
                    FieldName::IfModifiedSince => Field::IfModifiedSince(
                        HTTPDate::lift(field_values)
                            .map_err(|err| (err, field_name))?,
                    ),
                    FieldName::IfUnmodifiedSince => Field::IfUnmodifiedSince(
                        HTTPDate::lift(field_values)
                            .map_err(|err| (err, field_name))?,
                    ),
                    FieldName::IfRange => Field::IfRange(
                        IfRange::lift(field_values)
                            .map_err(|err| (err, field_name))?,
                    ),
                    FieldName::Server => Field::Server(
                        Server::lift(field_values)
                            .map_err(|err| (err, field_name))?,
                    ),
                    FieldName::UserAgent => Field::UserAgent(
                        UserAgent::lift(field_values)
                            .map_err(|err| (err, field_name))?,
                    ),
                    FieldName::NonStandard(..) => {
                        Field::NonStandard(RawField {
                            name: field_name.to_string(),
                            value: field_values
                                .into_iter()
                                .map(|RawFieldValue { value, .. }| {
                                    value.into_owned()
                                })
                                .collect::<Vec<_>>(),
                        })
                    }
                    name => todo!("{name}"),
                };

                fields.push(field_value);
            }

            Ok(Fields { values: fields })
        }

        let (_i, raw_fields) =
            field_lines.parse_complete(bytes).map_err(|err| match err {
                Err::Incomplete(..) => unreachable!(),
                Err::Error(error) | Err::Failure(error) => ParseError {
                    input: error.input.to_owned(),
                    kind: ParseErrorKind::Fields,
                },
            })?;

        Ok(lift_fields(raw_fields).map_err(|(input, field_name)| {
            ParseError {
                input,
                kind: ParseErrorKind::Field(field_name),
            }
        })?)
    }
}

impl FromByteStr for StartLine {
    type Err = String;

    fn from_bstr(bytes: &ByteStr) -> Result<Self, Self::Err> {
        let mut i = 0;

        macro_rules! throw {
            ($aspect:expr) => {
                Err(error!($aspect))?
            };
        }

        macro_rules! error {
            ($aspect:expr) => {
                format!("parsing {} failed", $aspect)
            };
        }

        macro_rules! offset {
            (=$c:literal ? $aspect:ident) => {{
                let c = $c;
                offset!(=c ? $aspect)
            }};
            (=$c:ident ? $aspect:ident) => {{
                let Some(offset) =
                    bytes[i..].iter().position(|b| *b == $c)
                else {
                    throw!(stringify!($aspect))
                };

                offset
            }};
        }

        macro_rules! consume {
            (s=$name:literal ? $aspect:ident) => {
                {
                    let name = $name;
                    consume!(s=name ? $aspect);
                }
            };
            (s=$name:ident ? $aspect:ident) => {
                let offset = $name.len();

                if bytes.len() < i + offset {
                    throw!(stringify!($aspect))
                }

                if &bytes[i..i + offset] == $name {
                    #[allow(unused)]
                    i += offset;
                }
                else {
                    throw!(stringify!($aspect))
                }
            };
            ({
                s=$name:literal => $e:path
                $(,s=$namex:literal => $ex:path)*
            } ? $aspect:ident
            ) =>
            {{
                let offset = $name.len();

                if bytes.len() < i + offset {
                    throw!(stringify!($aspect))
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
                    throw!(stringify!($aspect))
                }
            }};
            (c=$char:ident ? $aspect:ident) => {
                let offset = 1;

                if bytes.len() < i + offset {
                    throw!(stringify!($aspect))
                }

                if bytes[i] == $char {
                    i += offset;
                }
                else {
                    throw!(stringify!($aspect))
                }
            };
            (@$e:ident $offset:expr) => {{
                let offset = $offset;

                if bytes.len() < i + offset {
                    throw!(stringify!($e))
                }

                let raw = std::str::from_utf8(&bytes[i..i + offset])
                    .map_err(|_| error!(stringify!($e)))?;

                #[allow(unused)]
                i += offset;

                raw.parse::<$e>().map_err(|_| error!(stringify!($e)))?
            }};
        }

        struct MaybeString {
            value: Option<String>,
        }

        impl FromStr for MaybeString {
            type Err = Infallible;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Ok(Self {
                    value: if s.is_empty() {
                        Some(s.to_owned())
                    }
                    else {
                        None
                    },
                })
            }
        }

        enum State {
            Start,
            H,
            P,
            Request { method: Method },
            Response { version: Version },
        }

        use State::*;

        let mut state = Start;

        macro_rules! throw_state {
            ($state: ident) => {
                Err(match $state {
                    Start => "empty line".to_owned(),
                    H => error!("HTTP version or Method"),
                    P => error!("Method"),
                    Request { .. } => error!("RequestTarget"),
                    Response { .. } => error!("Status"),
                })?
            };
        }

        while i < bytes.len() {
            // startline is case-sensive
            state = match (state, bytes[i]) {
                // status line (response)
                (Start, b'H') => {
                    i += 1;

                    H
                }
                (Start, b'O') => {
                    consume!(s = b"OPTIONS" ? Method);

                    Request {
                        method: Method::Options,
                    }
                }
                (Start, b'G') => {
                    consume!(s = b"GET" ? Method);

                    Request {
                        method: Method::Get,
                    }
                }
                (Start, b'P') => {
                    i += 1;

                    P
                }
                (Start, b'D') => {
                    consume!(s = b"DELETE" ? Method);

                    Request {
                        method: Method::Delete,
                    }
                }
                (H, b'T') => {
                    /* parse status line */

                    consume!(s = b"TTP/" ? Version);

                    let version = consume!(
                        {
                            s=b"0.9" => Version::HTTP09,
                            s=b"1.0" => Version::HTTP10,
                            s=b"1.1" => Version::HTTP11
                        } ? Version
                    );

                    Response { version }
                }
                (H, b'E') => {
                    consume!(s = b"EAD" ? Method);

                    Request {
                        method: Method::Head,
                    }
                }
                (P, b'O') => {
                    consume!(s = b"OST" ? Method);

                    Request {
                        method: Method::Post,
                    }
                }
                (P, b'U') => {
                    consume!(s = b"UT" ? Method);

                    Request {
                        method: Method::Put,
                    }
                }
                (P, b'A') => {
                    consume!(s = b"ATCH" ? Method);

                    Request {
                        method: Method::Patch,
                    }
                }
                /* It may allow more lenient parsing that
                such whitespace includes one or more of the following octets:
                SP, HTAB, VT (%x0B), FF (%x0C), or bare CR
                (however it's not recommend) */
                (Request { method }, SP) => {
                    consume!(c = SP ? RWS);

                    let offset = offset!(=SP ? RWS);

                    let target = consume!(@RequestTarget offset);

                    consume!(c = SP ? RWS);

                    let version = consume!(@Version 8);

                    return Ok(StartLine::RequestLine(RequestLine {
                        method,
                        target,
                        version,
                    }));
                }
                (Response { version }, SP) => {
                    consume!(c = SP ? RWS);

                    let status = consume!(@StatusCode 3);

                    consume!(c = SP ? RWS);

                    let reason =
                        consume!(@MaybeString offset!(=b'\r' ? CR)).value;

                    return Ok(StartLine::StatusLine(StatusLine {
                        version,
                        status,
                        reason,
                    }));
                }
                (state, ..) => throw_state!(state),
            }
        }

        throw_state!(state)
    }
}

impl FromByteStr for ConnectionOption {
    type Err = String;

    fn from_bstr(bytes: &ByteStr) -> Result<Self, Self::Err> {
        bytes
            .decode_as_utf8()
            .map_err(|err| err.to_string())?
            .parse::<Self>()
            .map_err(|err| err.to_string())
    }
}

impl FromByteStr for ChunkHeader {
    type Err = String;

    fn from_bstr(bytes: &ByteStr) -> Result<Self, Self::Err> {
        let (_i, (size, ext)) = (chunk_size, chunk_ext)
            .parse_complete(bytes)
            .map_err(|err| err.to_string())?;

        Ok(Self { size, ext })
    }
}

impl FromByteStr for MediaType {
    type Err = String;

    fn from_bstr(bytes: &ByteStr) -> Result<Self, Self::Err> {
        let (_i, it) = media_type(bytes).map_err(|err| err.to_string())?;

        Ok(it)
    }
}

impl FromByteStr for IfRange {
    type Err = String;

    fn from_bstr(bytes: &ByteStr) -> Result<Self, Self::Err> {
        use IfRange::*;

        if let Ok((_i, tag)) = entity_tag(bytes) {
            Ok(Tag(tag))
        }
        else if let Ok(date) = bytes.parse::<HTTPDate>() {
            Ok(Date(date))
        }
        else {
            Err(format!("{bytes}"))
        }
    }
}

impl ConsumeByteStr for RequestTarget {
    type Err = ();

    fn consume_bstr(bytes: &ByteStr) -> Result<(Self, usize), Self::Err> {
        let (remains, it) = request_target(bytes).map_err(|_| ())?;

        Ok((it, bytes.len() - remains.len()))
    }
}

impl ConsumeByteStr for mime::MediaRangeType {
    type Err = ();

    fn consume_bstr(bytes: &ByteStr) -> Result<(Self, usize), Self::Err> {
        use mime::{MediaRangeType::*, MediaTopType::*};

        macro_rules! throw {
            () => {
                Err(())?
            };
        }

        let Some(dpos) = bytes.iter().position(|b| *b == b'/')
        else {
            throw!()
        };

        let Some(epos) = bytes[dpos + 1..].iter().position(|b| match *b {
            TCHAR![] => false,
            _ => true,
        })
        else {
            throw!()
        };

        // normalizaion str type
        let type_nstring =
            bytes[..dpos].decode_as_utf8().unwrap().to_lowercase();
        let subtype_nstring = bytes[dpos + 1..epos]
            .decode_as_utf8()
            .unwrap()
            .to_lowercase();

        let type_nstr = type_nstring.as_str();
        let subtype_nstr = subtype_nstring.as_str();

        let mime_range = match type_nstr {
            "*" => {
                if subtype_nstr == "*" {
                    StarStar
                }
                else {
                    throw!()
                }
            }
            "application" => unimplemented!(),
            "text" => {
                if type_nstr == "*" {
                    TypeStar(Text)
                }
                else {
                    TypeSubType(mime::MediaType::Text(
                        subtype_nstr.parse().map_err(|_| ())?,
                    ))
                }
            }
            "audio" | "font" | "haptics" | "image" | "message" | "model"
            | "multipart" | "video" => unimplemented!(),
            _ => throw!(),
        };

        Ok((mime_range, epos))
    }
}

impl ConsumeByteStr for UserAgent {
    type Err = ();

    fn consume_bstr(bytes: &ByteStr) -> Result<(Self, usize), Self::Err> {
        let (it, offset) = Server::consume_bstr(bytes)?;

        Ok((
            UserAgent {
                product: it.product,
                rem: it.rem,
            },
            offset,
        ))
    }
}

impl ConsumeByteStr for Server {
    type Err = ();

    fn consume_bstr(bytes: &ByteStr) -> Result<(Self, usize), Self::Err> {
        let (i, it) = server(bytes).map_err(|_| ())?;

        Ok((it, bytes.len() - i.len()))
    }
}

impl FromStr for FieldName {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (rems, _) =
            token(s).map_err(|s| format!("{s} is not valid token"))?;

        if !rems.is_empty() {
            Err(format!("rems {rems} is not valid token"))?
        }

        for name in Self::iter() {
            if matches!(name, Self::NonStandard(..)) {
                continue;
            }

            if name.to_string().eq_ignore_ascii_case(s) {
                return Ok(name);
            }
        }

        Ok(Self::NonStandard(CaseInsensitiveString::new(s)))
    }
}

impl FromStr for RangeUnit {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (rems, _) =
            token(s).map_err(|s| format!("{s} is not valid token"))?;

        if !rems.is_empty() {
            Err(format!("rems {rems} is not valid token"))?
        }

        for name in Self::iter() {
            if matches!(name, Self::Custom(..)) {
                continue;
            }

            if name.to_string().eq_ignore_ascii_case(s) {
                return Ok(name);
            }
        }

        Ok(Self::Custom(CaseInsensitiveString::new(s)))
    }
}

impl FromStr for Server {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = s.as_bytes();

        let server = Server::from_bstr(ByteStr::new(bytes))?;

        Ok(server)
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

        let Some(day_name_pos) = s.find(&[Space.to_char(), Comma.to_char()])
        else {
            Err(())?
        };

        let day_name = or_else!(s[..day_name_pos].parse::<DayName>());

        let s_rem_len = s[day_name_pos + 1..].len();

        if &s[day_name_pos..day_name_pos + 1] == "," {
            // IMF-fixdate or obsolete RFC 850 format
            if s_rem_len == 1 + 2 + 1 + 3 + 1 + 4 + 1 + 8 + 1 + 3 {
                s = &s[day_name_pos + 1..];

                require!(..1, Space);

                let day = or_else!(s[1..3].parse::<Day>());

                require!(3..4, Space);

                let month = or_else!(s[4..7].parse::<MonthName>());

                require!(7..8, Space);

                let year = or_else!(s[8..12].parse::<Year>());

                require!(12..13, Space);

                let time_of_day = or_else!(s[13..21].parse::<TimeOfDay>());

                require!(21..22, Space);

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

                require!(..1, Space);

                let day = or_else!(s[1..3].parse::<Day>());

                require!(3..4, HyphenMinus);

                let month = or_else!(s[4..7].parse::<MonthName>());

                require!(7..8, HyphenMinus);

                let year = or_else!(s[8..10].parse::<Year>());

                require!(10..12, Space);

                let time_of_day = or_else!(s[12..20].parse::<TimeOfDay>());

                require!(20..21, Space);

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

            require!(3..4, Space);

            let day = or_else!(s[4..6].trim_start().parse::<Day>());

            require!(6..7, Space);

            let time_of_day = or_else!(s[7..15].parse::<TimeOfDay>());

            require!(15..16, Space);

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

impl FromByteStr for Date {
    type Err = ();

    fn from_bstr(bytes: &ByteStr) -> Result<Self, Self::Err> {
        if let Ok(s) = std::str::from_utf8(bytes) {
            s.parse()
        }
        else {
            Err(())
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


impl FromStr for Year {
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.parse::<u16>()?))
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
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (it, n) = Self::consume_bstr(ByteStr::new(s))?;

        if s.len() > n { Err(()) } else { Ok(it) }
    }
}


////////////////////////////////////////////////////////////////////////////////
//// Functions

///
/// ```
/// use nonempty::nonempty;
///
/// use osimodel::application::http::parsing::ranges_specifier;
/// use osimodel::application::http::*;
///
/// let spec = ranges_specifier("bytes= 0-999, 4500-5499, -1000").unwrap().1;
/// assert_eq!(
///     spec.unit,
///     RangeUnit::Bytes
/// );
/// assert_eq!(
///     spec.set,
///     nonempty![
///         RangeSpec::IntRange {
///             start: 0,
///             end: Some(999)
///         },
///         RangeSpec::IntRange {
///             start: 4500,
///             end: Some(5499)
///         },
///         RangeSpec::SuffixRange {
///             end: 1000
///         }
///     ]
/// );
///
/// ```
///
/// ```abnf
/// ranges-specifier = range-unit "=" range-set
/// range-set        = OWS 1#range-spec
/// ```
///
pub fn ranges_specifier<I>(input: I) -> IResult<I, RangesSpecifier>
where
    I: Input + Offset + AsBytes,
    I::Item: AsByte,
{
    map(
        separated_pair(
            range_unit,
            byte(b'='),
            preceded(ows, list1(range_spec)),
        ),
        |(unit, set)| RangesSpecifier { unit, set },
    )
    .parse(input)
}

///
/// case-insensive
///
/// ```abnf
/// range-unit = token
/// ```
///
pub fn range_unit<I>(input: I) -> IResult<I, RangeUnit>
where
    I: Input + Offset + AsBytes,
    I::Item: AsByte,
{
    map_res(token, safe_as_str_parse).parse(input)
}

///
/// ```abnf
/// range-spec = int-range
///            / suffix-range
///            / other-range
/// ```
///
pub fn range_spec<I>(input: I) -> IResult<I, RangeSpec>
where
    I: Input + Offset + AsBytes,
    I::Item: AsByte,
{
    use RangeSpec::*;

    alt((
        map(int_range, |(start, end)| IntRange { start, end }),
        map(suffix_range, |end| SuffixRange { end }),
        map(other_range, |i| OtherRange(i)),
    ))
    .parse(input)
}

///
/// ```abnf
/// int-range = first-pos "-" [ last-pos ]
/// first-pos = 1*DIGIT
/// last-pos  = 1*DIGIT
/// ```
///
pub fn int_range<I>(input: I) -> IResult<I, (u64, Option<u64>)>
where
    I: Input + Offset + AsBytes,
    I::Item: AsByte,
{
    separated_pair(digit1_as_u64, byte(b'-'), on_guard_opt(digit1_as_u64))
        .parse(input)
}

///
/// ```abnf
/// suffix-range  = "-" suffix-length
/// suffix-length = 1*DIGIT
/// ```
///
pub fn suffix_range<I>(input: I) -> IResult<I, u64>
where
    I: Input + Offset + AsBytes,
    I::Item: AsByte,
{
    preceded(byte(b'-'), digit1_as_u64).parse(input)
}

///
/// ```abnf
/// other-range   = 1*( %x21-2B / %x2D-7E )
/// ; 1*(VCHAR excluding comma)
/// ```
///
pub fn other_range<I>(input: I) -> IResult<I, ByteString>
where
    I: Input + AsBytes,
    I::Item: AsByte,
{
    on_guard_fold_many1(
        satisfy(|b| match b {
            0x21..=0x2B | 0x2D..=0x7E => true,
            _ => false,
        }),
        ByteString::new,
        |mut bstr, b: I::Item| {
            bstr.push(b.as_byte());
            bstr
        },
    )
    .parse(input)
}

///
/// ```abnf
/// acceptable-ranges = 1#range-unit
/// ```
///
pub fn accecpt_ranges<I>(input: I) -> IResult<I, AcceptRanges>
where
    I: Input + Offset + AsBytes,
    I::Item: AsByte,
{
    map(list1(range_unit), |value| AcceptRanges { value }).parse(input)
}

///
/// ```
/// use nonempty::nonempty;
///
/// use osimodel::application::http::parsing::content_range;
/// use osimodel::application::http::*;
///
/// assert_eq!(
///     content_range("bytes 42-1233/1234").unwrap().1,
///     ContentRange {
///         unit: RangeUnit::Bytes,
///         range_or_unsatisfied: RangeOrUnsatisfied::Range(RangeResp {
///             range: 42..=1233,
///             complete_length: Some(1234)
///         })
///     }
/// );
///
/// assert_eq!(
///     content_range("bytes 42-1233/*").unwrap().1,
///     ContentRange {
///         unit: RangeUnit::Bytes,
///         range_or_unsatisfied:  RangeOrUnsatisfied::Range(RangeResp {
///             range: 42..=1233,
///             complete_length: None
///         })
///     }
/// );
/// ```
///
/// ```abnf
/// Content-Range = range-unit SP ( range-resp / unsatisfied-range )
/// ```
///
pub fn content_range<I>(input: I) -> IResult<I, ContentRange>
where
    I: Input + Offset + AsBytes,
    I::Item: AsByte,
{
    map(
        separated_pair(
            range_unit,
            sp,
            alt((
                map(range_resp, |range| RangeOrUnsatisfied::Range(range)),
                map(digit1_as_u64, |v| RangeOrUnsatisfied::Unsatisfied(v)),
            )),
        ),
        |(unit, range_or_unsatisfied)| ContentRange {
            unit,
            range_or_unsatisfied,
        },
    )
    .parse(input)
}

/// ```abnf
/// range-resp      = incl-range "/" ( complete-length / "*" )
/// incl-range      = first-pos "-" last-pos
/// complete-length = 1*DIGIT
/// ```
pub fn range_resp<I>(input: I) -> IResult<I, RangeResp>
where
    I: Input + Offset + AsBytes,
    I::Item: AsByte,
{
    map(
        separated_pair(
            incl_range,
            byte(b'/'),
            alt((map(digit1_as_u64, |v| Some(v)), value(None, byte(b'*')))),
        ),
        |(range, complete_length)| RangeResp {
            range,
            complete_length,
        },
    )
    .parse(input)
}

///
/// ```abnf
/// incl-range = first-pos "-" last-pos
/// first-pos  = 1*DIGIT
/// last-pos   = 1*DIGIT
/// ```
///
pub fn incl_range<I>(input: I) -> IResult<I, RangeInclusive<u64>>
where
    I: Input + Offset + AsBytes,
    I::Item: AsByte,
{
    map(
        separated_pair(digit1_as_u64, byte(b'-'), digit1_as_u64),
        |(start, end)| start..=end,
    )
    .parse(input)
}

///
/// for `BWS` to distinguish with parameters parser
///
/// ```abnf
/// transfer-coding    = token *( OWS ";" OWS transfer-parameter )
/// transfer-parameter = token BWS "=" BWS ( token / quoted-string )
/// ```
///
pub fn transfer_coding<I>(input: I) -> IResult<I, TransferCoding>
where
    I: Input + Offset + AsBytes,
    I::Item: AsByte,
{
    map(
        (
            map_res(token, |i| safe_as_str_parse(i)),
            on_guard_fold_many0(
                preceded((ows, byte(b';'), ows), transfer_parameter),
                Parameters::new,
                |params, p| params.parameter(p),
            ),
        ),
        |(coding, parameters)| TransferCoding { coding, parameters },
    )
    .parse(input)
}

/// transfer-parameter = token BWS "=" BWS ( token / quoted-string )
/// ```
///
pub fn transfer_parameter<I>(input: I) -> IResult<I, Parameter>
where
    I: Input + Offset + AsBytes,
    I::Item: AsByte,
{
    map(
        separated_pair(
            parameter_name,
            (bws, byte(b'='), bws),
            parameter_value,
        ),
        |(name, value)| Parameter { name, value },
    )
    .parse(input)
}

///
/// ```abnf
/// chunk-size = 1*HEXDIG
/// ```
///
pub fn chunk_size<I>(input: I) -> IResult<I, u32>
where
    I: Input + Offset + AsBytes,
    I::Item: AsByte,
{
    map_res(hexdig1, |i| u32::from_str_radix(safe_as_str(i), 16)).parse(input)
}

///
/// ```abnf
/// chunk-ext = *( BWS ";" BWS chunk-ext-name [ BWS "=" BWS chunk-ext-val] )
/// ```
///
pub fn chunk_ext<I>(input: I) -> IResult<I, ChunkExt>
where
    I: Input + Offset + AsBytes,
    I::Item: AsByte,
{
    on_guard_fold_many0(
        map(
            (
                preceded((bws, byte(b';'), bws), chunk_ext_name),
                on_guard_opt(preceded((bws, byte(b'='), bws), chunk_ext_val)),
            ),
            |(name, value)| ChunkExtUnit { name, value },
        ),
        ChunkExt::new,
        |mut ext, unit| {
            ext.push(unit);
            ext
        },
    )
    .parse(input)
}

///
/// ```abnf
/// chunk-ext-name = token
/// ```
///
pub fn chunk_ext_name<I>(input: I) -> IResult<I, String>
where
    I: Input + Offset + AsBytes,
    I::Item: AsByte,
{
    map(token, safe_to_string).parse(input)
}

///
/// ```abnf
/// chunk-ext-val = token / quoted-string
/// ```
///
pub fn chunk_ext_val<I>(input: I) -> IResult<I, ParameterValue>
where
    I: Input + Offset + AsBytes,
    I::Item: AsByte,
{
    parameter_value.parse(input)
}

///
/// ```abnf
/// charset = ( token / "*" )
/// ```
///
pub fn charset<I>(input: I) -> IResult<I, Charset>
where
    I: Input + Offset + AsBytes,
    I::Item: AsByte,
{
    use Charset::*;

    alt((
        map_res(token, |i: I| {
            safe_as_str_parse::<_, charset::Charset>(i).map(|it| Spec(it))
        }),
        value(Star, byte(b'*')),
    ))
    .parse(input)
}

///
/// ```
/// use osimodel::application::http::parsing::entity_tag;
/// use osimodel::application::http::EntityTag;
///
/// assert_eq!(entity_tag(r#""xyzzy""#).map(|(_, v)| v), Ok(EntityTag {
///     is_weak: false,
///     opaque_tag: "xyzzy".as_bytes().into()
/// }));
///
/// assert_eq!(entity_tag(r#"W/"xyzzy""#).map(|(_, v)| v), Ok(EntityTag {
///     is_weak: true,
///     opaque_tag: "xyzzy".as_bytes().into()
/// }));
/// ```
///
/// ```abnf
/// entity-tag = [ weak ] opaque-tag
/// weak       = %s"W/" ; case-sensitive
/// ```
///
pub fn entity_tag<I>(input: I) -> IResult<I, EntityTag>
where
    I: Input + Offset + AsBytes + Compare<&'static str>,
    I::Item: AsByte,
{
    map(
        (on_guard_opt(tag("W/")), opaque_tag),
        |(opt_w, opaque_tag)| EntityTag {
            is_weak: opt_w.is_some(),
            opaque_tag,
        },
    )
    .parse(input)
}

///
/// ```
/// use osimodel::application::http::parsing::if_match;
/// use osimodel::application::http::{ IfMatch::*, EntityTag };
///
/// assert_eq!(
///     if_match(r#""xyzzy", "r2d2xxxx", "c3piozzzz""#).unwrap().1,
///     List(vec![
///         EntityTag {
///             is_weak: false,
///             opaque_tag: "xyzzy".as_bytes().into()
///         },
///         EntityTag {
///             is_weak: false,
///             opaque_tag: "r2d2xxxx".as_bytes().into()
///         },
///         EntityTag {
///             is_weak: false,
///             opaque_tag: "c3piozzzz".as_bytes().into()
///         }]
///     ),
/// );
///
/// assert_eq!(if_match("*").unwrap().1, Star);
///
/// ```
///
/// ```abnf
/// If-Match = "*" / #entity-tag
/// ```
///
pub fn if_match<I>(input: I) -> IResult<I, IfMatch>
where
    I: Input + Offset + AsBytes + Compare<&'static str>,
    I::Item: AsByte,
{
    use IfMatch::*;

    alt((
        value(Star, byte(b'*')),
        map(list(entity_tag), |vec| List(vec)),
    ))
    .parse(input)
}

///
/// ```abnf
/// opaque-tag = DQUOTE *etagc DQUOTE
/// ```
///
pub fn opaque_tag<I>(input: I) -> IResult<I, ByteString>
where
    I: Input + Offset + AsBytes,
    I::Item: AsByte,
{
    delimited(
        byte(b'"'),
        on_guard_fold_many0(
            satisfy(|b| matches!(b, ETAGC![])),
            ByteString::new,
            |mut s, c: I::Item| {
                s.push(c.as_byte());
                s
            },
        ),
        byte(b'"'),
    )
    .parse(input)
}



///
/// ```abnf
/// Server = product *( RWS ( product-or-comment ) )
/// ```
///
pub fn server<I>(input: I) -> IResult<I, Server>
where
    I: Input + Offset + AsBytes,
    I::Item: AsByte,
{
    map(
        (product, on_guard_many0(preceded(rws, product_or_comment))),
        |(product, rem)| Server { product, rem },
    )
    .parse(input)
}

///
/// ```abnf
/// product-or-comment = product / comment
/// ```
///
pub fn product_or_comment<I>(input: I) -> IResult<I, ProductOrComment>
where
    I: Input + Offset + AsBytes,
    I::Item: AsByte,
{
    use ProductOrComment::*;

    alt((
        map(product, |prod| Product(prod)),
        map(comment, |comm: I| {
            Comment(ByteStr::new(comm.as_bytes()).to_owned())
        }),
    ))
    .parse(input)
}

///
/// ```abnf
/// product = token ["/" token]
/// ```
///
pub fn product<I>(input: I) -> IResult<I, Product>
where
    I: Input + Offset + AsBytes,
    I::Item: AsByte,
{
    map_res(
        (token, on_guard_opt(preceded(byte(b'/'), token))),
        |(name, opt_version)| {
            Ok::<_, Err<Error<I>>>(Product {
                name: safe_to_string(name),
                version: opt_version.map(|version| safe_to_string(version)),
            })
        },
    )
    .parse(input)
}

///
/// ```abnf
/// codings = content-coding / "identity" / "*"
/// ```
pub fn codings<I>(input: I) -> IResult<I, Codings>
where
    I: Input + Offset + Compare<&'static str> + AsBytes,
    I::Item: AsByte,
{
    use Codings::*;

    alt((
        value(Star, byte(b'*')),
        value(Identity, tag_no_case("identity")),
        map_res(token, |t: I| {
            Ok::<_, <ContentCoding as FromStr>::Err>(Spec(safe_as_str_parse(
                t,
            )?))
        }),
    ))
    .parse(input)
}

///
/// ```abnf
/// Host = uri-host [ ":" port ]
/// ```
pub fn host<I>(input: I) -> IResult<I, Host>
where
    I: Input + Offset + AsBytes + Compare<&'static str>,
    I::Item: AsByte,
{
    map(
        (uri_host, on_guard_opt(preceded(byte(b':'), port))),
        |(host, port)| Host { host, port },
    )
    .parse(input)
}

///
/// ```abnf
///  media-range = ( "*/*"
///                  / ( type "/" "*" )
///                  / ( type "/" subtype )
///                ) parameters
/// ```
///
pub fn media_range<I>(input: I) -> IResult<I, MediaRange>
where
    I: Input + Offset + AsBytes + Compare<&'static str>,
    I::Item: AsByte,
{
    use mime::MediaRangeType::*;

    map(
        (
            alt((
                map(tag("*/*"), |_| StarStar),
                map_res(terminated(r#type, tag("/*")), |s| {
                    Ok::<_, <MediaTopType as FromStr>::Err>(TypeStar(
                        s.parse::<MediaTopType>()?,
                    ))
                }),
                map(mime_media_type, |mime| TypeSubType(mime)),
            )),
            parameters,
        ),
        |(mime, parameters)| MediaRange { mime, parameters },
    )
    .parse(input)
}

///
/// ```abnf
/// media-type = mime-media-type parameters
/// ```
///
pub fn media_type<I>(input: I) -> IResult<I, MediaType>
where
    I: Input + Offset + AsBytes,
    I::Item: AsByte,
{
    map((mime_media_type, parameters), |(mime, parameters)| {
        MediaType { mime, parameters }
    })
    .parse(input)
}

///
/// ```abnf
/// mime-media-type = type "/" subtype
/// type       = token
/// subtype    = token
/// ```
///
pub fn mime_media_type<I>(input: I) -> IResult<I, mime::MediaType>
where
    I: Input + Offset + AsBytes,
    I::Item: AsByte,
{
    map_res(
        separated_pair(r#type, byte(b'/'), subtype),
        |(top_type, sub_type)| {
            use MediaTopType::*;

            let top_type = top_type.parse::<MediaTopType>()?;

            Ok::<mime::MediaType, strum::ParseError>(match top_type {
                Application => mime::MediaType::Application(
                    sub_type.parse::<ApplicationType>()?,
                ),
                Audio => todo!(),
                Font => todo!(),
                Haptics => todo!(),
                Image => todo!(),
                Message => {
                    mime::MediaType::Message(sub_type.parse::<MessageType>()?)
                }
                Model => todo!(),
                Multipart => mime::MediaType::Multipart(
                    sub_type.parse::<MultipartType>()?,
                ),
                Text => mime::MediaType::Text(sub_type.parse::<TextType>()?),
                Video => todo!(),
            })
        },
    )
    .parse(input)
}

///
/// ```abnf
/// type = token
/// ```
///
pub fn r#type<'i, I>(input: I) -> IResult<I, &'i str>
where
    I: Input + Offset + AsBytes + 'i,
    I::Item: AsByte,
{
    map(token, safe_as_str).parse(input)
}

///
/// ```abnf
/// subtype = token
/// ```
///
pub fn subtype<'i, I>(input: I) -> IResult<I, &'i str>
where
    I: Input + Offset + AsBytes + 'i,
    I::Item: AsByte,
{
    r#type(input)
}

// pub fn field_media_type<'i, I>(
//     input: I,
// ) -> IResult<I, MediaType>
// where
//     I: Input + Offset + AsBytes,
//     I::Item: AsByte,
//     {

//     }

///
/// ```abnf
/// field-lines = *( field-line CRLF )
/// ```
///
pub fn field_lines<'i, I>(input: I) -> IResult<I, RawFields<'i>>
where
    I: Input + Offset + AsBytes + 'i,
    I::Item: AsByte,
{
    on_guard_fold_many0(
        terminated(field_line, crlf),
        HashMap::<FieldName, NonEmpty<RawFieldValue<'i>>>::new,
        |mut map, (name, value)| {
            match map.entry(name) {
                Entry::Occupied(mut occupied) => {
                    occupied.get_mut().push(RawFieldValue { value });
                }
                Entry::Vacant(vacant) => {
                    vacant.insert(NonEmpty::new(RawFieldValue { value }));
                }
            }
            map
        },
    )
    .parse(input)
}

///
/// ```abnf
/// field-line = field-name ":" OWS *(field-value obs-fold) field-value OWS
/// ```
///
pub fn field_line<'i, I>(
    input: I,
) -> IResult<I, (FieldName, FlatCow<'i, ByteStr>)>
where
    I: Input + Offset + AsBytes,
    I::Item: AsByte,
{
    map(
        (
            field_name,
            byte(b':'),
            ows,
            map(
                on_guard_many0(terminated(field_value::<I>, obs_fold)),
                |values| {
                    if values.len() == 0 {
                        FlatCow::own_new(ByteString::new())
                    }
                    else if values.len() == 1 {
                        FlatCow::borrow_new(unsafe {
                            ByteStr::from_bytes_permanently(
                                values[0].as_bytes(),
                            )
                        })
                    }
                    else {
                        /*join with space */

                        let size = values
                            .iter()
                            .map(|v| v.as_bytes().len())
                            .sum::<usize>()
                            + (values.len() - 1);

                        let mut owned = ByteString::with_capacity(size);

                        let mut iter = values.into_iter();

                        owned.push_str(ByteStr::new(
                            iter.next().unwrap().as_bytes(),
                        ));

                        for v in iter {
                            owned.push(SP);
                            owned.push_str(ByteStr::new(v.as_bytes()));
                        }

                        FlatCow::own_new(owned)
                    }
                },
            ),
            map(field_value::<I>, |i: I| {
                FlatCow::borrow_new(unsafe {
                    ByteStr::from_bytes_permanently(i.as_bytes())
                })
            }),
            ows,
        ),
        |(name, _colon, _ows1, mut folds, last_value, _ows2)| {
            let value = if folds.is_empty() {
                last_value
            }
            else {
                folds.to_mut().push_str(&last_value);
                folds
            };

            (name, value)
        },
    )
    .parse(input)
}

///
/// ```
/// obs-fold = OWS CRLF RWS
///          ; obsolete line folding
/// ```
///
pub fn obs_fold<I>(input: I) -> IResult<I, I>
where
    I: Input + Offset,
    I::Item: AsByte,
{
    recognize((ows, crlf, rws)).parse(input)
}

///
/// bad white space
///
pub fn bws<I>(input: I) -> IResult<I, I>
where
    I: Input + Offset,
    I::Item: AsByte,
{
    ows(input)
}

///
/// optional white space
///
pub fn ows<I>(input: I) -> IResult<I, I>
where
    I: Input + Offset,
    I::Item: AsByte,
{
    recognize(on_guard_many0(ws)).parse(input)
}

///
/// required white space
///
pub fn rws<I>(input: I) -> IResult<I, I>
where
    I: Input + Offset,
    I::Item: AsByte,
{
    recognize(on_guard_many1(ws)).parse(input)
}

///
/// ```abnf
/// field-name = token
/// ```
///
pub fn field_name<I>(input: I) -> IResult<I, FieldName>
where
    I: Input + Offset + AsBytes,
    I::Item: AsByte,
{
    map(token, |i: I| safe_as_str_parse::<I, FieldName>(i).unwrap())
        .parse(input)
}

///
/// ```abnf
/// token = 1*tchar
/// ```
///
pub fn token<I>(input: I) -> IResult<I, I>
where
    I: Input + Offset,
    I::Item: AsByte,
{
    recognize(on_guard_many1(tchar)).parse(input)
}

///
/// ```abnf
/// token = 1*(tchar / "/")
/// ```
///
pub fn token_with_slash<I>(input: I) -> IResult<I, I>
where
    I: Input + Offset,
    I::Item: AsByte,
{
    recognize(on_guard_many1(alt((tchar, recognize(byte(b'/')))))).parse(input)
}

///
/// ```abnf
/// tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*"
///       / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~"
///       / DIGIT / ALPHA
///       ; any VCHAR, except delimiters
/// ```
///
pub fn tchar<I>(input: I) -> IResult<I, I>
where
    I: Input + Offset,
    I::Item: AsByte,
{
    recognize(satisfy(|b| matches!(b, TCHAR![]))).parse(input)
}

///
/// ```abnf
/// field-value = *field-content
/// ```
///
pub fn field_value<I>(input: I) -> IResult<I, I>
where
    I: Input + Offset,
    I::Item: AsByte,
{
    recognize(on_guard_many0(field_content)).parse(input)
}

///
/// ```abnf
/// field-content  = field-vchar
///                  [ 1*( SP / HTAB / field-vchar ) field-vchar ]
/// ```
pub fn field_content<I>(input: I) -> IResult<I, I>
where
    I: Input + Offset,
    I::Item: AsByte,
{
    recognize((
        field_vchar,
        on_guard_opt((
            on_guard_many1(satisfy(|b| matches!(b, WS![] | FIELD_VCHAR![]))),
            field_vchar,
        )),
    ))
    .parse(input)
}

///
/// ```abnf
/// field-vchar = VCHAR / obs-text
/// ```
///
pub fn field_vchar<I>(input: I) -> IResult<I, I::Item>
where
    I: Input,
    I::Item: AsByte,
{
    satisfy(|b| matches!(b, FIELD_VCHAR![])).parse(input)
}

///
/// ```abnf
/// quoted-string = DQUOTE *( qdtext / quoted-pair ) DQUOTE
/// ```
///
pub fn quoted_string<I>(input: I) -> IResult<I, ByteString>
where
    I: Input,
    I::Item: AsByte,
{
    delimited(
        byte(b'"'),
        map(
            on_guard_fold_many0(
                alt((qdtext, quoted_pair)),
                ByteString::new,
                |mut s, c: I::Item| {
                    s.push(c.as_byte());
                    s
                },
            ),
            |i| i.into(),
        ),
        byte(b'"'),
    )
    .parse(input)
}

///
/// ```abnf
/// qdtext = HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text
/// ```
///
pub fn qdtext<I>(input: I) -> IResult<I, I::Item>
where
    I: Input,
    I::Item: AsByte,
{
    satisfy(|b| matches!(b, QDTEXT![])).parse(input)
}

///
/// ```abnf
/// quoted-pair = "\" ( HTAB / SP / VCHAR / obs-text )
/// ```
///
pub fn quoted_pair<I>(input: I) -> IResult<I, I::Item>
where
    I: Input,
    I::Item: AsByte,
{
    preceded(
        byte(b'\\'),
        satisfy(|b| matches!(b, WS![] | FIELD_VCHAR![])),
    )
    .parse(input)
}

///
/// ```abnf
/// comment = "(" *( ctext / quoted-pair / comment ) ")"
/// ```
///
pub fn comment<I>(input: I) -> IResult<I, I>
where
    I: Input + Offset,
    I::Item: AsByte,
{
    delimited(
        byte(LPAREN),
        recognize(on_guard_many0(alt((
            recognize(ctext),
            recognize(quoted_pair),
            comment,
        )))),
        byte(RPAREN),
    )
    .parse(input)
}

///
/// ```abnf
/// ctext = HTAB / SP / %x21-27 / %x2A-5B / %x5D-7E / obs-text
/// ```
///
pub fn ctext<I>(input: I) -> IResult<I, I::Item>
where
    I: Input,
    I::Item: AsByte,
{
    satisfy(|b| matches!(b, CTEXT![])).parse(input)
}

///
/// ```
/// use osimodel::application::http::parsing::weight;
///
/// assert_eq!(weight(" ;q=0.24").map(|(_, v)| v), Ok(0.24f32));
/// ```
///
/// ```abnf
/// weight = OWS ";" OWS "q=" qvalue
/// ```
///
pub fn weight<I>(input: I) -> IResult<I, f32>
where
    I: Input + Offset + AsBytes + Compare<&'static str>,
    I::Item: AsByte,
{
    preceded((ows, byte(b';'), ows, tag_no_case("q=")), qvalue).parse(input)
}

pub fn decimal_u32<I>(input: I) -> IResult<I, u32>
where
    I: Input + Offset + AsBytes,
    I::Item: AsByte,
{
    map_res(digit1, |s| safe_as_str_parse(s)).parse(input)
}

///
/// ```rust
/// use osimodel::application::http::parsing::qvalue;
///
/// assert_eq!(qvalue("0.24").map(|(_, v)| v), Ok(0.24f32));
/// assert_eq!(qvalue("1.").map(|(_, v)| v), Ok(1f32));
/// ```
///
/// ```abnf
/// qvalue = ( "0" [ "." 0*3DIGIT ] )
///        / ( "1" [ "." 0*3("0") ] )
/// ```
///
///
pub fn qvalue<I>(input: I) -> IResult<I, f32>
where
    I: Input + Offset + AsBytes,
    I::Item: AsByte,
{
    map_res(
        alt((
            recognize((
                byte(b'0'),
                on_guard_opt((byte(b'.'), take_while_m_n(0, 3, is_digit))),
            )),
            recognize((
                byte(b'1'),
                on_guard_opt((
                    byte(b'.'),
                    take_while_m_n(0, 3, |b: I::Item| b.as_byte() == b'0'),
                )),
            )),
        )),
        |i| safe_as_str_parse(i),
    )
    .parse(input)
}

///
/// ```abnf
/// parameters = *( OWS ";" OWS [ parameter ] )
/// ```
///
pub fn parameters<I>(input: I) -> IResult<I, Parameters>
where
    I: Input + Offset + AsBytes,
    I::Item: AsByte,
{
    on_guard_fold_many0(
        (ows, byte(b';'), ows, opt(parameter)),
        Parameters::new,
        |mut params, (_ows1, _semi, _ows2, opt_param)| {
            if let Some(p) = opt_param {
                params.push(p);
            }

            params
        },
    )
    .parse(input)
}

///
/// ```abnf
/// parameter = parameter-name "=" parameter-value
/// ```
///
pub fn parameter<I>(input: I) -> IResult<I, Parameter>
where
    I: Input + Offset + AsBytes,
    I::Item: AsByte,
{
    map(
        separated_pair(parameter_name, byte(b'='), parameter_value),
        |(name, value)| Parameter { name, value },
    )
    .parse(input)
}

///
/// ```abnf
/// parameter-name  = token ; and shouldn't eq 'q'/'Q' in semantics
/// ```
///
pub fn parameter_name<I>(input: I) -> IResult<I, String>
where
    I: Input + Offset + AsBytes,
    I::Item: AsByte,
{
    verify(map(token, safe_to_string), |s: &str| s != "q" && s != "Q")
        .parse(input)
}

///
/// ```abnf
/// parameter-value = ( token / quoted-string )
/// ```
///
pub fn parameter_value<I>(input: I) -> IResult<I, ParameterValue>
where
    I: Input + Offset + AsBytes,
    I::Item: AsByte,
{
    use ParameterValue::*;

    alt((
        map(token, |i: I| Token(safe_to_string(i))),
        map(quoted_string, |i| QStr(i)),
    ))
    .parse(input)
}

///
/// ```abnf
/// list = [ list1 ]  ; #f
/// ```
///
fn list<I, F>(
    f: F,
) -> impl Parser<
    I,
    Output = Vec<<F as Parser<I>>::Output>,
    Error = <F as Parser<I>>::Error,
>
where
    I: Input + Offset,
    F: Parser<I, Error = nom::error::Error<I>> + Copy,
    I::Item: AsByte,
{
    map(on_guard_opt(list1(f)), |opt_nonempty| {
        if let Some(nonempty) = opt_nonempty {
            nonempty.into()
        }
        else {
            Vec::new()
        }
    })
}

///
/// ```abnf
/// list1 = f *( OWS "," OWS f )  ; 1#f
/// ```
///
fn list1<I, F>(
    f: F,
) -> impl Parser<
    I,
    Output = NonEmpty<<F as Parser<I>>::Output>,
    Error = <F as Parser<I>>::Error,
>
where
    I: Input + Offset,
    F: Parser<I, Error = nom::error::Error<I>> + Copy,
    I::Item: AsByte,
{
    map(
        (f, on_guard_many0(preceded((ows, byte(b','), ows), f))),
        |(a, rems)| NonEmpty {
            head: a,
            tail: rems,
        },
    )
}

///
/// filter out empty value
///
/// ```abnf
/// part = *( comment ) [(quoted-string / token)] *( comment )
/// line = part *( OWS "," OWS part )
/// ```
///
fn field_list_based<'a>(
    filed_values: &'a NonEmpty<RawFieldValue<'a>>,
) -> RawParseResult<Vec<RawFieldValue<'a>>> {
    fn part<'a, I>(input: I) -> IResult<I, RawFieldValue<'a>>
    where
        I: Input + Offset + AsBytes,
        I::Item: AsByte,
    {
        delimited(
            on_guard_many0(comment),
            alt((
                map(quoted_string, |s| RawFieldValue {
                    value: FlatCow::own_new(s),
                }),
                map(token_with_slash, |i: I| RawFieldValue {
                    value: unsafe {
                        FlatCow::borrow_new(ByteStr::from_bytes_permanently(
                            i.as_bytes(),
                        ))
                    },
                }),
                map(empty, |_| RawFieldValue {
                    value: FlatCow::own_new(ByteString::new()),
                }),
            )),
            on_guard_many0(comment),
        )
        .parse(input)
    }

    fn line<'a, I>(input: I) -> IResult<I, NonEmpty<RawFieldValue<'a>>>
    where
        I: Input + Offset + AsBytes,
        I::Item: AsByte,
    {
        map(
            (
                part,
                on_guard_fold_many0(
                    preceded((ows, byte(b','), ows), part),
                    Vec::new,
                    |mut vec, p| {
                        vec.push(p);
                        vec
                    },
                ),
            ),
            |(head, tail)| NonEmpty { head, tail },
        )
        .parse(input)
    }

    let mut members = vec![];

    for field_value in filed_values {
        let (_i, nonempty) = line(field_value.deref())
            .map_err(|_err| field_value.deref().to_owned())?;

        members.extend(nonempty.into_iter().filter(|s| !s.is_empty()));
    }

    Ok(members)
}

fn map_res_singleton<'a, T, E2>(
    field_values: &'a NonEmpty<RawFieldValue<'a>>,
    mut f: impl FnMut(&RawFieldValue<'a>) -> Result<T, E2>,
) -> RawParseResult<T> {
    let input = &field_values.head;

    f(&input).map_err(|_err| input.deref().to_owned())
}

fn map_parser_singleton<'a: 'b, 'b, T>(
    field_values: &'a NonEmpty<RawFieldValue<'a>>,
    mut parser: impl Parser<&'b ByteStr, Output = T, Error = Error<&'b ByteStr>>,
) -> RawParseResult<T> {
    let input = &field_values.head;

    let res = parser
        .parse(input.deref())
        .map_err(|_err| input.deref().to_owned())
        .map(|(_i, it)| it);

    res
}

fn fold_map_parser_field_list<'a: 'b, 'b, T, C>(
    field_values: &'a [RawFieldValue<'a>],
    mut f: impl Parser<&'b ByteStr, Output = T, Error = Error<&'b ByteStr>>,
    g: impl Fn(Vec<T>) -> C,
) -> RawParseResult<C> {
    let mut vec = Vec::with_capacity(field_values.len());

    for v in field_values {
        match f.parse(&v.value.as_ref()) {
            Ok((_i, it)) => vec.push(it),
            Result::Err(_err) => Err(v.deref().to_owned())?,
        }
    }

    Ok(g(vec))
}

fn fold_map_res_field_list<'a, T, C, E2>(
    field_values: &'a [RawFieldValue<'a>],
    mut f: impl FnMut(&RawFieldValue<'a>) -> Result<T, E2>,
    g: impl Fn(Vec<T>) -> C,
) -> RawParseResult<C> {
    let mut vec = Vec::with_capacity(field_values.len());

    for v in field_values {
        vec.push(f(&v).map_err(|_| v.deref().to_owned())?)
    }

    Ok(g(vec))
}



#[cfg(test)]
mod tests {
    use m6io::{bstr::ToByteString, bstr};

    use super::*;

    #[test]
    fn test_split_list() {
        fn part<'a, I>(input: I) -> IResult<I, RawFieldValue<'a>>
        where
            I: Input + Offset + AsBytes,
            I::Item: AsByte,
        {
            delimited(
                on_guard_many0(comment),
                alt((
                    map(quoted_string, |s| RawFieldValue {
                        value: FlatCow::own_new(s),
                    }),
                    map(token_with_slash, |i: I| RawFieldValue {
                        value: unsafe {
                            FlatCow::borrow_new(
                                ByteStr::from_bytes_permanently(i.as_bytes()),
                            )
                        },
                    }),
                    map(empty, |_| RawFieldValue {
                        value: FlatCow::own_new(ByteString::new()),
                    }),
                )),
                on_guard_many0(comment),
            )
            .parse(input)
        }

        let (_i, it) = part(bstr!(b"*/*")).unwrap();

        println!("part: {it:#?}");
    }

    #[test]
    fn test_parse_media_range() {
        let input = bstr!("*/*");

        println!("{:#?}", media_range(input).unwrap());
    }

    #[test]
    fn test_parse_transfer_encoding() {
        let input = bstr!("chunked");

        println!("{:#?}", transfer_coding(input).unwrap());
    }

    #[test]
    fn test_parse_comment() {
        let input = bstr!("(linux (ubuntu))");

        println!("{:#?}", comment(input).unwrap());
    }

    #[test]
    fn test_parse_server() {
        let serv_name = b"SHTTPD/0.0.1 (Linux)";
        let serv = ByteStr::new(serv_name).parse::<Server>().unwrap();

        let ProductOrComment::Comment(comment) = &serv.rem[0]
        else {
            unreachable!()
        };

        assert_eq!(
            serv.to_bstring(),
            serv_name,
            "{};{}",
            comment.decode_as_utf8().unwrap(),
            serv.to_bstring().decode_as_utf8().unwrap()
        );

        let serv_name = b"SHTTPD/0.0.1 (Linux (Ubuntu))";
        let serv = ByteStr::new(serv_name).parse::<Server>().unwrap();
        let ProductOrComment::Comment(comment) = &serv.rem[0]
        else {
            unreachable!()
        };

        assert_eq!(
            serv.to_bstring(),
            serv_name,
            "{serv:#?};{};{}",
            comment.decode_as_utf8().unwrap(),
            serv.to_bstring().decode_as_utf8().unwrap()
        );

        let serv_name = b"SHTTPD/0.0.1 (Linux) (Ubuntu)";
        let serv = ByteStr::new(serv_name).parse::<Server>().unwrap();

        assert_eq!(
            serv.to_bstring(),
            serv_name,
            "{serv:#?};{}",
            serv.to_bstring().decode_as_utf8().unwrap()
        );
    }

    #[test]
    fn test_parse_start_line() {
        bstr!("/").parse::<RequestTarget>().unwrap();

        let StartLine::RequestLine(request_line) =
            bstr!("GET / HTTP/1.1").parse::<StartLine>().unwrap()
        else {
            unreachable!()
        };

        let RequestTarget::Origin { abs_path, .. } = request_line.target
        else {
            unreachable!()
        };

        assert_eq!(abs_path, "/");

        bstr!("GET / HTTP/1.1").parse::<StartLine>().unwrap();

        bstr!("GET www.baidu.com HTTP/1.1")
            .parse::<StartLine>()
            .unwrap();

        bstr!("HEAD / HTTP/1.1").parse::<StartLine>().unwrap();

        bstr!("POST / HTTP/1.1").parse::<StartLine>().unwrap();

        bstr!("OPTIONS / HTTP/1.1").parse::<StartLine>().unwrap();
    }

    #[test]
    fn test_parse_fields() {
        let raw = "Accept: */*\r
Accept-Encoding: gzip, deflate\r
Connection: keep-alive\r
Transfer-Encoding: chunked\r
Host: localhost\r
";

        let input = ByteStr::new(raw);

        let (_i, raw_fields) = field_lines(input).unwrap();

        println!("raw_fields: {raw_fields:#?}");

        let ae_field_values =
            raw_fields.get(&FieldName::AcceptEncoding).unwrap();
        let ae_field_value_list = field_list_based(ae_field_values).unwrap();

        println!("ae_field_values: {ae_field_values:?}");
        println!("ae_field_value_list: {ae_field_value_list:?}");

        let a_field_values = raw_fields.get(&FieldName::Accept).unwrap();
        let a_field_value_list = field_list_based(a_field_values).unwrap();

        println!("a_field_values: {a_field_values:?}");
        println!("a_field_value_list: {a_field_value_list:?}");

        let fields = Fields::from_bstr(input).unwrap();

        println!("{fields:#?}");
    }
}
