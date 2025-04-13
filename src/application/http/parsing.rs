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
    str::FromStr,
};

use m6io::{ByteStr, ConsumeByteStr, CowBuf, FlatCow, FromByteStr};
use nom::{character::char, combinator::{map, opt}, Parser};

use super::{uri::{ host, port, request_target, to_string }, *};

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

/// 0..=9
macro_rules! DIGIT {
    () => {
        b'0'..=b'9'
    };
}

macro_rules! ALPHA {
    () => {
        b'a'..=b'z' | b'A'..=b'Z'
    };
}

macro_rules! FIELD_VCHAR {
    () => {
        WS![] | VCHAR![] | OBS_TEXT![]
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

/// obs-text, obsoleted chars, viewed as opaque data
macro_rules! OBS_TEXT {
    () => {
        0x80..=0xFF
    };
}

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

macro_rules! HEXDIG {
    () => {
        DIGIT![] | b'A'..=b'F' | b'a'..=b'f'
    };
}

macro_rules! require_singleton_value {
    ($name:expr, $raw_fields:ident) => {{
        if $raw_fields.len() > 1 {
            Err(format!("{} require singleton value", stringify!($name)))?;
        }

        $raw_fields.remove(0)
    }};
}

macro_rules! field_error {
    ($name:ident, $err:expr) => {
        format!("Invalid filed `{}`: {}", stringify!($name), $err)
    };
}

////////////////////////////////////////////////////////////////////////////////
//// Constants

const HTAB: u8 = CharacterTabulation.to_u8();
const SP: u8 = Space.to_u8();
const LPAREN: u8 = LeftParenthesis.to_u8();
const RPAREN: u8 = RightParenthesis.to_u8();


trait LiftFieldValue<'a>: Sized {
    fn lift(raw_field_values: Vec<RawFieldValue<'a>>) -> Result<Self, String>;
}


////////////////////////////////////////////////////////////////////////////////
//// Structures

struct MaybeString {
    value: Option<String>,
}

type RawFields<'a> = HashMap<FlatCow<'a, str>, Vec<RawFieldValue<'a>>>;

#[derive(Debug, Clone, Deref)]
struct RawFieldValue<'a> {
    value: FlatCow<'a, ByteStr>,
}

////////////////////////////////////////////////////////////////////////////////
//// Implementations

impl<'a> LiftFieldValue<'a> for Host {
    fn lift(
        mut raw_field_values: Vec<RawFieldValue<'a>>,
    ) -> Result<Self, String> {
        let value = require_singleton_value!(Host, raw_field_values);

        value.value.parse().map_err(|err| field_error!(Host, err))
    }
}

impl<'a> LiftFieldValue<'a> for AcceptCharset {
    fn lift(raw_field_values: Vec<RawFieldValue<'a>>) -> Result<Self, String> {
        let Some(_members) = split_list_field_value(raw_field_values)?
        else {
            unreachable!()
        };

        todo!()
    }
}

impl<'a> LiftFieldValue<'a> for Accept {
    fn lift(raw_field_values: Vec<RawFieldValue<'a>>) -> Result<Self, String> {
        let Some(members) = split_list_field_value(raw_field_values)?
        else {
            unreachable!()
        };

        let values = members
            .into_iter()
            .map(|member| {
                let RawFieldValue { mut value, .. } = member;

                let (media_range, range_type_offset) =
                    mime::MediaRangeType::consume_bstr(&value).map_err(
                        |_| field_error!(Accept, "Invalid MediaRange"),
                    )?;

                value = value.as_slice_cow(range_type_offset..);

                let (parameters, parameters_offset) =
                    Parameters::consume_bstr(&value).map_err(|_| {
                        field_error!(Accept, "Invalid Parameters")
                    })?;

                let weight = consume_maybe_weight(&value[parameters_offset..])
                    .map_err(|_| field_error!(Accept, "Invalid weight"))?
                    .map(|x| x.0)
                    .unwrap_or(1.0);

                Ok::<(MediaRange, f32), String>((
                    MediaRange {
                        mime: media_range,
                        parameters,
                    },
                    weight,
                ))
            })
            .try_collect::<Vec<(MediaRange, f32)>>()?;

        Ok(Self { values })
    }
}

impl<'a> LiftFieldValue<'a> for Connection {
    fn lift(raw_field_values: Vec<RawFieldValue<'a>>) -> Result<Self, String> {
        let Some(members) = split_list_field_value(raw_field_values)?
        else {
            unreachable!()
        };

        Ok(Self {
            value: members
                .try_map(|member| member.parse::<ConnectionOption>())?,
        })
    }
}

impl<'a> LiftFieldValue<'a> for MediaType {
    fn lift(
        mut raw_field_values: Vec<RawFieldValue<'a>>,
    ) -> Result<Self, String> {
        let RawFieldValue { value, .. } =
            require_singleton_value!(MediaType, raw_field_values);

        let media_type = Self::from_bstr(&value)
            .map_err(|_| field_error!(MediaType, ""))?;

        Ok(media_type)
    }
}

///
/// ```abnf
/// *( field-line CRLF )
/// ```
///
impl FromByteStr for Fields {
    type Err = String;

    fn from_bstr(bytes: &ByteStr) -> Result<Self, Self::Err> {
        fn parse_raw_fields<'a>(bytes: &ByteStr) -> Result<RawFields, String> {
            let mut i = 0;
            let mut fields: RawFields = HashMap::new();

            while i < bytes.len() {
                /* prase field name */

                let (field_name, offset) = consume_token(&bytes[i..].into());

                i += offset;

                if bytes[i] != Colon.into() {
                    Err("expect `:` after field name {field_name}".to_owned())?;
                }

                i += 1;

                /* consume option white spaces */

                i += consume_ws(&bytes[i..]);

                /* parse field value */

                let (mut field_value, offset) =
                    consume_field_value(&bytes[i..].into());

                i += offset;

                /* consume option white spaces */

                i += consume_ws(&bytes[i..]);

                /* consume CRLF */

                i += consume_crlf(&bytes[i..])
                    .map_err(|_| format!("lack CRLF after {field_name}"))?;

                while i < bytes.len() {
                    match bytes[i] {
                        WS![] => {
                            /*  obsolete line folding (replace CRLF with SP) */

                            /* consume OBS */

                            i += consume_ws(&bytes[i..]);

                            /* insert(replace CRLF) space  */

                            field_value.to_mut().push(SP);

                            let (next_line, offset) =
                                consume_field_value(&bytes[i..].into());

                            field_value.to_mut().push_str(&next_line);
                            i += offset;

                            /* consume OBS */

                            i += consume_ws(&bytes[i..]);

                            /* consume CRLF */

                            i += consume_crlf(&bytes[i..]).map_err(|_| {
                                format!("lack CRLF after {field_name}")
                            })?;
                        }
                        _ => break,
                    }
                }

                /* push field */

                let field_value = RawFieldValue { value: field_value };

                match fields.entry(field_name) {
                    Entry::Occupied(mut occupied) => {
                        occupied.get_mut().push(field_value);
                    }
                    Entry::Vacant(vacant) => {
                        vacant.insert(vec![field_value]);
                    }
                }
            }

            Ok(fields)
        }

        fn lift_fields(raw_fields: RawFields) -> Result<Fields, String> {
            let mut fields = Vec::new();

            for (raw_field_name, raw_field_value) in raw_fields.into_iter() {
                let field_name = raw_field_name.parse::<FieldName>().unwrap();

                debug_assert!(!raw_field_value.is_empty());

                let field_value = match &field_name {
                    FieldName::Connection => {
                        Field::Connection(Connection::lift(raw_field_value)?)
                    }
                    FieldName::Host => {
                        Field::Host(Host::lift(raw_field_value)?)
                    }
                    FieldName::ContentType => {
                        Field::ContentType(MediaType::lift(raw_field_value)?)
                    }
                    FieldName::NonStandard(..) => {
                        Field::NonStandard(RawField {
                            name: raw_field_name.into_owned(),
                            value: raw_field_value
                                .into_iter()
                                .map(|RawFieldValue { value, .. }| {
                                    value.into_owned()
                                })
                                .collect::<Vec<_>>(),
                        })
                    }
                    _ => todo!(),
                };

                fields.push(field_value);
            }

            Ok(Fields { fields })
        }

        Ok(lift_fields(parse_raw_fields(bytes)?)?)
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
            Finish(StartLine),
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
                    _ => unreachable!(),
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

                    let target = consume!(@RequestTarget offset!(=SP ? RWS));

                    consume!(c = SP ? RWS);

                    let version = consume!(@Version 8);

                    Finish(StartLine::RequestLine(RequestLine {
                        method,
                        target,
                        version,
                    }))
                }
                (Response { version }, SP) => {
                    consume!(c = SP ? RWS);

                    let status = consume!(@StatusCode 3);

                    consume!(c = SP ? RWS);

                    let reason =
                        consume!(@MaybeString offset!(=b'\r' ? CR)).value;

                    Finish(StartLine::StatusLine(StatusLine {
                        version,
                        status,
                        reason,
                    }))
                }
                (Finish(startline), ..) => {
                    consume!(s = b"\r\n" ? CRLF);

                    return Ok(startline);
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

        let (size, offset) = consume_hexdigits_u32(bytes)
            .map_err(|err| format!("parse chunk size failed for {err}"))?;

        i += offset;

        let ext = bytes[i..].parse::<ChunkExt>()?;

        Ok(Self { size, ext })
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
                    i += consume_ws(&bytes[i..]);
                    Start
                }
                (Start, b';') => {
                    i += 1;
                    AfterSemi
                }
                (AfterSemi, WS![]) => {
                    i += consume_ws(&bytes[i..]);
                    AfterSemi
                }
                (AfterSemi, TCHAR![]) => {
                    let (ext_name, offset) = consume_token(&bytes[i..].into());
                    i += offset;
                    i += consume_ws(&bytes[i..]);

                    AfterExtName(ext_name.into_owned())
                }
                (AfterExtName(ext_name), b';') => {
                    ext.push(ValueOrPair::Value(ext_name));
                    Start
                }
                (AfterExtName(ext_name), b'=') => {
                    i += 1;
                    i += consume_ws(&bytes[i..]);

                    let ext_value = bytes[i..].parse::<PairValue>()?;

                    ext.push(ValueOrPair::Pair(Pair {
                        name: ext_name,
                        value: ext_value,
                    }));

                    i += consume_ws(&bytes[i..]);

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

impl ConsumeByteStr for Host {
    type Err = String;

    fn consume_bstr(bytes: &ByteStr) -> Result<(Self, usize), Self::Err> {
        let (remains, it) = map((host, opt((char(':'), port))), |(host, opt_p)| Self {
            host: to_string(host),
            port: opt_p.map(|(_, p)| p)
        })
        .parse(bytes).map_err(|err| err.to_string())?;

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

impl ConsumeByteStr for Server {
    type Err = ();

    fn consume_bstr(bytes: &ByteStr) -> Result<(Self, usize), Self::Err> {
        let mut i = 0;

        let (product, product_offset) = Product::consume_bstr(bytes)?;
        i += product_offset;

        let mut rem = vec![];

        while i < bytes.len() {
            i += consume_ws(&bytes[i..]);

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
                        PairValue::consume_bstr(&bytes[i..])?;

                    i += offset;

                    parameters.push(Pair {
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


impl ConsumeByteStr for PairValue {
    type Err = String;

    fn consume_bstr(bytes: &ByteStr) -> Result<(Self, usize), Self::Err> {
        use PairValue::*;

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

        if s.len() > n {
            Err(())
        }
        else {
            Ok(it)
        }
    }
}


////////////////////////////////////////////////////////////////////////////////
//// Functions

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
                buf.clone_push(b);

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

fn consume_field_value<'a>(
    bytes: &FlatCow<'a, ByteStr>,
) -> (FlatCow<'a, ByteStr>, usize) {
    let mut i = 0;

    while i < bytes.len() {
        match bytes[i] {
            FIELD_VCHAR![] => (),
            _ => break,
        }

        i += 1;
    }

    (bytes.as_slice_cow(..i), i)
}

fn consume_crlf(bytes: &ByteStr) -> Result<usize, ()> {
    if bytes.len() < 4 {
        Err(())?;
    }

    if bytes == b"\r\n" { Ok(4) } else { Err(()) }
}

fn consume_maybe_weight(bytes: &ByteStr) -> Result<Option<(f32, usize)>, ()> {
    let mut i = 0;

    /* consume maybe space */

    i += consume_ws(bytes);

    if i < bytes.len() && bytes[i] == Semicolon.to_u8() {
        i += 1;
    }
    else {
        return Ok(None);
    }

    i += consume_ws(bytes);

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

fn consume_ws(bytes: &ByteStr) -> usize {
    let mut i = 0;

    /* consume maybe space */

    while i < bytes.len() {
        match bytes[i] {
            WS![] => (),
            _ => break,
        }

        i += 1;
    }

    i
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

fn consume_hexdig_str(bytes: &ByteStr) -> (&str, usize) {
    let mut i = 0;

    while i < bytes.len() {
        match bytes[i] {
            HEXDIG![] => (),
            _ => break,
        }

        i += 1;
    }

    (bytes[..i].decode_as_utf8().unwrap(), i)
}

fn consume_hexdigits_u32(bytes: &ByteStr) -> Result<(u32, usize), String> {
    let (s, offset) = consume_hexdig_str(bytes);

    u32::from_str_radix(s, 16)
        .map_err(|err| err.to_string())
        .map(|v| (v, offset))
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

fn split_list_field_value<'a>(
    filed_values: Vec<RawFieldValue<'a>>,
) -> Result<Option<NonEmpty<RawFieldValue<'a>>>, String> {
    let mut members = vec![];

    use QuotingEnv::*;
    use State::*;

    let mut state = Normal;

    #[derive(Clone, Copy)]
    enum State {
        Normal,
        InComment(usize),
        InStr,
        Quoting(QuotingEnv),
    }

    #[derive(Clone, Copy)]
    enum QuotingEnv {
        Comment(usize),
        Str,
    }

    for field_value in filed_values.into_iter() {
        let RawFieldValue { value, .. } = field_value;

        let mut ep = 0; // end point

        for (i, b) in value.iter().cloned().enumerate() {
            state = match (state, b) {
                (Normal, b'"') => InStr,
                (Normal, LPAREN) => InComment(1),
                (Normal, b',') => {
                    members.push(RawFieldValue {
                        value: value.as_slice_cow(ep..i),
                    });
                    ep = i;
                    state
                }
                (Normal, _) => state,
                (InStr, QDTEXT![]) => state,
                (InComment(..), CTEXT![]) => state,
                (InStr | InComment(..), b'\\') => Quoting(match state {
                    InStr => Str,
                    InComment(cnt) => Comment(cnt),
                    _ => unreachable!(),
                }),
                (Quoting(env), WS![] | VCHAR![] | OBS_TEXT![]) => match env {
                    Str => InStr,
                    Comment(cnt) => InComment(cnt),
                },
                (InStr, b'"') => Normal,
                (InComment(cnt), RPAREN) => {
                    if cnt > 0 {
                        InComment(cnt - 1)
                    }
                    else {
                        Normal
                    }
                }
                _ => Err("split list-based filed value failed")?,
            }
        }
    }

    Ok(NonEmpty::from_vec(members))
}


#[cfg(test)]
mod tests {
    use m6io::ToByteString;

    use super::*;

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
        let StartLine::RequestLine(request_line) = ByteStr::new(b"GET / HTTP/1.1").parse::<StartLine>().unwrap() else {
            unreachable!()
        };

        let RequestTarget::Origin { abs_path, .. } = request_line.target else { unreachable!() };

        assert_eq!(
            abs_path,
            "/"
        );
    }
}
