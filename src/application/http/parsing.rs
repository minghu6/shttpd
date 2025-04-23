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
    nom::{
        byte::{byte, crlf, digit1, is_digit, is_ws, satisfy, ws}, on_guard_fold_many0, on_guard_many0, on_guard_many1, on_guard_opt, safe_as_str, safe_as_str_parse, safe_to_string, AsByte
    }, ByteStr, ConsumeByteStr, CowBuf, FlatCow, FromByteStr, ToByteString, ALPHA, DIGIT, WS
};
use nom::{
    AsBytes, Compare, Err, IResult, Input, Offset, Parser,
    branch::alt,
    bytes::{tag, tag_no_case, take_while_m_n},
    combinator::{complete, map, map_res, opt, recognize, verify},
    error::{Error, ErrorKind, ParseError},
    sequence::{delimited, preceded, separated_pair, terminated},
};
use stringcase::train_case;

use super::{
    uri::{host as uri_host, port, request_target},
    *,
};
use crate::application::mime::{MediaTopType, MessageType, TextType};

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

struct MaybeString {
    value: Option<String>,
}

type RawFields<'a> = HashMap<FieldName, NonEmpty<RawFieldValue<'a>>>;

#[derive(Deref)]
#[deref(forward)]
struct RawFieldValue<'a> {
    value: FlatCow<'a, ByteStr>,
}

type RawParseResult<T> = Result<T, Err<Error<ByteString>>>;

#[derive(Deref)]
#[deref(forward)]
struct RawFieldValues<'a> {
    value: NonEmpty<RawFieldValue<'a>>,
}

////////////////////////////////////////////////////////////////////////////////
//// Implementations

impl<'a> Debug for RawFieldValue<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.value.decode_as_utf8() {
            Ok(s) => write!(f, "{s}"),
            Err(_) => write!(f, "[non-utf8-compatiable-data]"),
        }
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
        todo!()
    }
}

impl<'a> LiftFieldValue<'a> for Accept {
    fn lift(
        raw_field_values: NonEmpty<RawFieldValue<'a>>,
    ) -> RawParseResult<Self> {
        fold_map_parser_field_list(
            &field_list_based(&raw_field_values)?,
            (media_range, weight),
            |values| Self { values },
        )
    }
}

impl<'a> LiftFieldValue<'a> for Connection {
    fn lift(
        raw_field_values: NonEmpty<RawFieldValue<'a>>,
    ) -> RawParseResult<Self> {
        fold_map_res_field_list(
            field_list_based(&raw_field_values)?,
            |v| safe_as_str_parse(v.deref()),
            |value| Connection { value },
        )
    }
}

impl<'a> LiftFieldValue<'a> for MediaType {
    fn lift(
        raw_field_values: NonEmpty<RawFieldValue<'a>>,
    ) -> RawParseResult<Self> {
        map_parser_singleton(&raw_field_values, media_type)
    }
}

///
/// ```abnf
/// *( field-line CRLF )
/// ```
///
impl FromByteStr for Fields {
    type Err = nom::error::Error<ByteString>;

    fn from_bstr(bytes: &ByteStr) -> Result<Self, Self::Err> {
        fn lift_fields(raw_fields: RawFields) -> Result<Fields, ()> {
            let mut fields = Vec::new();

            // for (raw_field_name, raw_field_value) in raw_fields.into_iter() {
            //     let field_name = raw_field_name.parse::<FieldName>().unwrap();

            //     let field_value = match &field_name {
            //         FieldName::Connection => {
            //             Field::Connection(Connection::lift(raw_field_value)?)
            //         }
            //         FieldName::Host => {
            //             Field::Host(Host::lift(raw_field_value)?)
            //         }
            //         FieldName::ContentType => {
            //             Field::ContentType(MediaType::lift(raw_field_value)?)
            //         }
            //         FieldName::NonStandard(..) => {
            //             Field::NonStandard(RawField {
            //                 name: raw_field_name.into_owned(),
            //                 value: raw_field_value
            //                     .into_iter()
            //                     .map(|RawFieldValue { value, .. }| {
            //                         value.into_owned()
            //                     })
            //                     .collect::<Vec<_>>(),
            //             })
            //         }
            //         _ => todo!(),
            //     };

            //     fields.push(field_value);
            // }

            Ok(Fields { fields })
        }

        let (i, raw_fields) =
            field_lines.parse_complete(bytes).map_err(|err| match err {
                Err::Incomplete(..) => unreachable!(),
                Err::Error(error) | Err::Failure(error) => Error {
                    input: error.input.to_owned(),
                    code: error.code,
                },
            })?;

        Ok::<Self, Self::Err>(lift_fields(raw_fields).unwrap())
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

        dbg!("{}", bytes.decode_as_utf8().unwrap());

        while i < bytes.len() {
            // startline is case-sensive
            state = match (state, bytes[i]) {
                // status line (response)
                (Start, b'H') => H,
                (Start, b'O') => {
                    consume!(s = b"Options" ? Method);

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
                (H, b'e') => {
                    consume!(s = b"EAD" ? Method);

                    Request {
                        method: Method::Head,
                    }
                }
                (P, b'o') => {
                    consume!(s = b"OST" ? Method);

                    Request {
                        method: Method::Post,
                    }
                }
                (P, b'u') => {
                    consume!(s = b"UT" ? Method);

                    Request {
                        method: Method::Put,
                    }
                }
                (P, b'a') => {
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

// impl FromStr for StartLine {
//     type Err = String;

//     fn from_str(s: &str) -> Result<Self, Self::Err> {
//         ByteStr::new(s.as_bytes()).parse()
//     }
// }

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
        let mut i = 0;

        // let (size, offset) = consume_hexdigits_u32(bytes)
        //     .map_err(|err| format!("parse chunk size failed for {err}"))?;

        // i += offset;

        // let ext = bytes[i..].parse::<ChunkExt>()?;

        // Ok(Self { size, ext })

        todo!()
    }
}

impl FromByteStr for ChunkExt {
    type Err = String;

    fn from_bstr(bytes: &ByteStr) -> Result<Self, Self::Err> {
        use State::*;

        let mut i = 0;
        let mut ext = Self::new();
        let mut state = Start;

        enum State {
            Start,
            AfterSemi,
            AfterExtName(String),
        }

        while i < bytes.len() {
            state = match (state, bytes[i]) {
                (Start, WS![]) => {
                    // i += consume_ws(&bytes[i..]);
                    Start
                }
                (Start, b';') => {
                    i += 1;
                    AfterSemi
                }
                (AfterSemi, WS![]) => {
                    // i += consume_ws(&bytes[i..]);
                    AfterSemi
                }
                (AfterSemi, TCHAR![]) => {
                    let (ext_name, offset) = consume_token(&bytes[i..].into());
                    i += offset;
                    // i += consume_ws(&bytes[i..]);

                    AfterExtName(ext_name.into_owned())
                }
                (AfterExtName(ext_name), b';') => {
                    ext.push(ValueOrPair::Value(ext_name));
                    Start
                }
                (AfterExtName(ext_name), b'=') => {
                    i += 1;
                    // i += consume_ws(&bytes[i..]);

                    let ext_value = bytes[i..].parse::<ParameterValue>()?;

                    ext.push(ValueOrPair::Pair(Parameter {
                        name: ext_name,
                        value: ext_value,
                    }));

                    // i += consume_ws(&bytes[i..]);

                    Start
                }
                _ => Err("malformed chunk-ext".to_owned())?,
            };
        }

        match state {
            Start | AfterSemi => (), // ignore case
            AfterExtName(ext_name) => ext.push(ValueOrPair::Value(ext_name)),
        }

        Ok(ext)
    }
}

impl ConsumeByteStr for RequestTarget {
    type Err = ();

    fn consume_bstr(bytes: &ByteStr) -> Result<(Self, usize), Self::Err> {
        let (remains, it) = request_target(bytes).map_err(|_| ())?;

        Ok((it, bytes.len() - remains.len()))
    }
}

// impl ConsumeByteStr for Host {
//     type Err = String;

//     fn consume_bstr(bytes: &ByteStr) -> Result<(Self, usize), Self::Err> {
//         let it = map_parser_singleton(bytes, host)?;

//         Ok((it, bytes.len() - remains.len()))
//     }
// }

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

impl ConsumeByteStr for Server {
    type Err = ();

    fn consume_bstr(bytes: &ByteStr) -> Result<(Self, usize), Self::Err> {
        let mut i = 0;

        let (product, product_offset) = Product::consume_bstr(bytes)?;
        i += product_offset;

        let mut rem = vec![];

        while i < bytes.len() {
            // i += consume_ws(&bytes[i..]);

            if bytes[i] == LPAREN {
                let (comment, comment_offset) =
                    consume_comment(bytes[i..].into())?;

                i += comment_offset;

                rem.push(ProductOrComment::Comment(comment.into_owned()));
            }
            else {
                let (product_next, product_next_offset) =
                    Product::consume_bstr(bytes[i..].into())?;

                i += product_next_offset;

                rem.push(ProductOrComment::Product(product_next));
            }
        }

        Ok((Self { product, rem }, i))
    }
}

impl<'o> ConsumeByteStr for Product {
    type Err = ();

    fn consume_bstr(bytes: &ByteStr) -> Result<(Self, usize), Self::Err> {
        let mut i = 0;

        let (name, name_offset) = consume_token(&bytes.into());
        i += name_offset;

        let version = if bytes[i] == b'/' {
            i += 1;
            let (version, version_offset) = consume_token(&bytes[i..].into());

            i += version_offset;
            Some(version)
        }
        else {
            None
        };

        Ok((
            Self {
                name: name.into_owned(),
                version: version.map(|v| v.into_owned()),
            },
            i,
        ))
    }
}

impl ConsumeByteStr for MediaType {
    type Err = ();

    fn consume_bstr(bytes: &ByteStr) -> Result<(Self, usize), Self::Err> {
        macro_rules! throw {
            () => {
                Err(())?
            };
        }

        let Some(dpos) = bytes.iter().position(|b| *b == b'/')
        else {
            throw!()
        };

        let Some(e_offset) = bytes[dpos + 1..].iter().position(|b| match *b {
            TCHAR![] => false,
            _ => true,
        })
        else {
            throw!()
        };

        let epos = dpos + 1 + e_offset;

        let mime = match bytes[..dpos]
            .decode_as_utf8()
            .unwrap()
            .to_lowercase()
            .as_str()
        {
            "application" => unimplemented!(),
            "text" => mime::MediaType::Text(
                bytes[dpos + 1..epos]
                    .decode_as_utf8()
                    .unwrap()
                    .parse()
                    .map_err(|_| ())?,
            ),
            "audio" | "font" | "haptics" | "image" | "message" | "model"
            | "multipart" | "video" => unimplemented!(),
            _ => throw!(),
        };

        let (parameters, p_offset) =
            Parameters::consume_bstr(&bytes[epos..]).map_err(|_| ())?;

        Ok((Self { mime, parameters }, epos + p_offset))
    }
}

impl ConsumeByteStr for Parameters {
    type Err = String;

    fn consume_bstr(bytes: &ByteStr) -> Result<(Self, usize), Self::Err> {
        use State::*;

        #[derive(Clone, Copy)]
        enum State {
            Start,
            InPreOWS,
            InPostOWS,
        }

        let mut parameters = Parameters::new();

        let mut i = 0;
        let mut pre_i = 0; // for `q`
        let mut state = Start;

        while i < bytes.len() {
            state = match (state, bytes[i]) {
                (Start, WS![]) => {
                    i += 1;

                    InPreOWS
                }
                (Start | InPreOWS, b';') => {
                    pre_i = i;
                    i += 1;

                    InPostOWS
                }
                (InPreOWS | InPostOWS, WS![]) => {
                    i += 1;

                    state
                }
                (InPostOWS, TCHAR![]) => {
                    let (param_name, offset) =
                        consume_token(&bytes[i..].into());
                    i += offset;

                    // disjoin with optional weight
                    if param_name == "q" {
                        i = pre_i;
                        break;
                    }

                    if i == bytes.len() {
                        Err("empty parameter value".to_owned())?;
                    }

                    let (param_value, offset) =
                        ParameterValue::consume_bstr(&bytes[i..])?;

                    i += offset;

                    parameters.push(Parameter {
                        name: param_name.into_owned(),
                        value: param_value,
                    });

                    InPreOWS
                }
                (_, _) => Err("malformed parameters".to_owned())?,
            };
        }

        Ok((parameters, i))
    }
}


impl ConsumeByteStr for ParameterValue {
    type Err = String;

    fn consume_bstr(bytes: &ByteStr) -> Result<(Self, usize), Self::Err> {
        use ParameterValue::*;

        let (pair_value, offset) = if !bytes.is_empty() && bytes[0] == b'"' {
            let (qstr, offset) = consume_qstr(&bytes.into())
                .map_err(|_| "malformed quoted-string")?;

            (QStr(qstr.into_owned()), offset)
        }
        else {
            let (token, offset) = consume_token(&bytes.into());

            (Token(token.into_owned()), offset)
        };

        Ok((pair_value, offset))
    }
}

impl ConsumeByteStr for ContentLength {
    type Err = String;

    fn consume_bstr(bytes: &ByteStr) -> Result<(Self, usize), Self::Err> {
        let (s, offset) = consume_decimal_str(bytes);

        Ok((
            Self {
                value: s.parse::<u64>().map_err(|err| err.to_string())?,
            },
            offset,
        ))
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
                Application => todo!(),
                Audio => todo!(),
                Font => todo!(),
                Haptics => todo!(),
                Image => todo!(),
                Message => {
                    mime::MediaType::Message(sub_type.parse::<MessageType>()?)
                }
                Model => todo!(),
                Multipart => todo!(),
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
fn field_lines<'i, I>(input: I) -> IResult<I, RawFields<'i>>
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
    I: Input + Offset + AsBytes,
    for<'a> I: Compare<&'a str>,
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
/// first byte is double-quote
///
/// return (parsed-bytes (exclude double quote), offset)
///
fn consume_qstr<'a>(
    bytes: &FlatCow<'a, ByteStr>,
) -> Result<(FlatCow<'a, ByteStr>, usize), ()> {
    use State::*;

    let mut state = Start;
    let mut buf = CowBuf::from(bytes);

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
            (Start, b'"') => {
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
            (InStr, b'\\') => Quoting,
            (Quoting, WS![] | VCHAR![] | OBS_TEXT![]) => {
                buf.clone_push(bytes[i]);

                InStr
            }
            (InStr, b'"') => OutStr,
            _ => break,
        };

        i += 1;
    }

    match state {
        OutStr => Ok((buf.to_cow(), i)),
        _ => Err(()),
    }
}

/// return (str, offset)
fn consume_token<'a>(
    bytes: &FlatCow<'a, ByteStr>,
) -> (FlatCow<'a, str>, usize) {
    let mut i = 0;

    while i < bytes.len() {
        match bytes[i] {
            TCHAR![] => (),
            _ => break,
        }

        i += 1;
    }

    (bytes.as_slice_cow(..i).try_into().unwrap(), i)
}


fn consume_maybe_weight(bytes: &ByteStr) -> Result<Option<(f32, usize)>, ()> {
    let mut i = 0;

    /* consume maybe space */

    // i += consume_ws(bytes);

    if i < bytes.len() && bytes[i] == Semicolon.to_u8() {
        i += 1;
    }
    else {
        return Ok(None);
    }

    // i += consume_ws(bytes);

    if i + 2 < bytes.len()
        && (&bytes[i..i + 2] == b"q=" || &bytes[i..i + 2] == b"Q=")
    {
        i += 2;
    }

    if i == bytes.len() {
        Err(())?;
    }

    let b = bytes[i];

    if b != b'0' && b != b'1' {
        Err(())?;
    }

    let mut j = i + 1;

    Ok(Some(if j < bytes.len() && bytes[j] == b'.' {
        if b == b'0' {
            while (j - i) <= 3 {
                match bytes[j] {
                    b'0'..=b'9' => (),
                    _ => break,
                }

                j += 1;
            }

            (
                bytes[i..j]
                    .decode_as_utf8()
                    .unwrap()
                    .parse::<f32>()
                    .map_err(|_| ())?,
                j,
            )
        }
        else {
            while (j - i) <= 3 {
                if bytes[j] != b'0' {
                    break;
                }

                j += 1;
            }

            (1.0, j)
        }
    }
    else {
        ((b - b'0') as f32, j)
    }))
}


fn consume_decimal_str(bytes: &ByteStr) -> (&str, usize) {
    let mut i = 0;

    while i < bytes.len() {
        match bytes[i] {
            DIGIT![] => (),
            _ => break,
        }

        i += 1;
    }

    (bytes[..i].decode_as_utf8().unwrap(), i)
}


/// another impl style (without explicit state)
fn consume_comment<'a>(
    bytes: FlatCow<'a, ByteStr>,
) -> Result<(FlatCow<'a, ByteStr>, usize), ()> {
    let mut i = 0;
    let mut cnt = 0;
    let mut escaping = false;
    let mut buf = CowBuf::from(&bytes);

    if bytes.is_empty() || bytes[0] != LPAREN {
        Err(())?
    }

    buf.start(1);

    for b in bytes.iter().cloned() {
        if escaping {
            match b {
                WS![] | VCHAR![] | OBS_TEXT![] => buf.clone_push(b),
                _ => Err(())?,
            }

            escaping = false;
        }
        else {
            match b {
                b'(' => {
                    if cnt > 0 {
                        buf.push(b);
                    }

                    cnt += 1;
                }
                b')' => {
                    if cnt == 0 {
                        Err(())?
                    }
                    else if cnt == 1 {
                        i += 2;
                        break;
                    }
                    else {
                        buf.push(b);
                        cnt -= 1;
                    }
                }
                b'\\' => {
                    escaping = true;
                }
                CTEXT![] => {
                    if cnt == 0 {
                        Err(())?
                    }

                    buf.push(b);
                }
                _ => Err(())?,
            }
        }

        i += 1;
    }

    Ok((buf.to_cow(), i))
}


///
/// ```abnf
/// part = *( comment ) (quoted-string / token) *( comment )
/// line = part *( OWS "," OWS part )
/// ```
///
fn field_list_based<'a>(
    filed_values: &'a NonEmpty<RawFieldValue<'a>>,
) -> RawParseResult<NonEmpty<RawFieldValue<'a>>> {
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
                map(token, |i: I| RawFieldValue {
                    value: unsafe {
                        FlatCow::borrow_new(ByteStr::from_bytes_permanently(
                            i.as_bytes(),
                        ))
                    },
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
            .map_err(|err| err.map_input(ToOwned::to_owned))?;

        members.extend(nonempty);
    }

    Ok(NonEmpty::from_vec(members).unwrap())
}

fn map_singleton<'a, T, E2>(
    field_values: &'a NonEmpty<RawFieldValue<'a>>,
    mut f: impl FnMut(&RawFieldValue<'a>) -> Result<T, E2>,
) -> RawParseResult<T> {
    let input = &field_values.head;

    f(&input).map_err(|_err| {
        Err::Error(Error {
            input: input.deref().to_owned(),
            code: ErrorKind::MapRes,
        })
    })
}

fn map_parser_singleton<'a: 'b, 'b, T>(
    field_values: &'a NonEmpty<RawFieldValue<'a>>,
    mut parser: impl Parser<&'b ByteStr, Output = T, Error = Error<&'b ByteStr>>,
) -> RawParseResult<T> {
    let input = &field_values.head;

    let res = parser.parse(input.deref()).map_err(|err| {
        err.map_input(|i| i.to_bstring())
    }).map(|(_i, it)| it);

    res
}

fn fold_map_parser_field_list<'a: 'b, 'b, T, C>(
    field_values: &'a NonEmpty<RawFieldValue<'a>>,
    mut f: impl Parser<&'b ByteStr, Output = T, Error = Error<&'b ByteStr>>,
    g: impl Fn(NonEmpty<T>) -> C,
) -> RawParseResult<C> {
    let mut vec = Vec::with_capacity(field_values.len());

    for v in field_values {
        match f.parse(&v.value.as_ref()) {
            Ok((_i, it)) => {
                vec.push(it)
            }
            Result::Err(err) => {
                Err(err.map_input(|i| i.to_bstring()))?
            },
        }
    }

    Ok(g(NonEmpty::from_vec(vec).unwrap()))
}

fn fold_map_res_field_list<'a, T, C, E2>(
    field_values: NonEmpty<RawFieldValue<'a>>,
    mut f: impl FnMut(&RawFieldValue<'a>) -> Result<T, E2>,
    g: impl Fn(NonEmpty<T>) -> C,
) -> RawParseResult<C> {
    let mut vec = Vec::with_capacity(field_values.len());

    for v in field_values {
        vec.push(f(&v).map_err(|_| {
            Err::Error(Error {
                input: v.value.into_owned(),
                code: ErrorKind::MapRes,
            })
        })?)
    }

    Ok(g(NonEmpty::from_vec(vec).unwrap()))
}



#[cfg(test)]
mod tests {
    use m6io::{ToByteString, bstr};

    use super::*;

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
    }

    #[test]
    fn test_parse_fields() {
        let raw = "Accept: */*\r
Accept-Encoding: gzip, deflate\r
Connection: keep-alive\r
Host: localhost\r
";

        let raw = ByteStr::new(raw);

        // println!("{:?}", alt::<()>((field_vchar, ws)).parse(r"\a"))
    }
}
