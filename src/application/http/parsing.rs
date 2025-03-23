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
    error::Error,
    ops::Deref,
    str::FromStr,
};

use ParseErrorReason::*;
use derive_more::derive::Display;
use m6parsing::Span;
use m6ptr::{
    ByteStr, ConsumeBytesInto, CowBuf, FlatCow, FromBytesInto,
};

use super::*;

////////////////////////////////////////////////////////////////////////////////
//// Macros

macro_rules! safe_decode_str {
    ($bytes:expr) => {
        unsafe { std::str::from_utf8_unchecked($bytes) }
    };
}

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

/// VCHAR exclude delimiters `"(),/:;<=>?@[\]{}"`
macro_rules! TCHAR {
    () => {
        b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' |
        b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~' |
        DIGIT![] | ALPHA![]
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

macro_rules! require_singleton_value {
    ($raw_field_values: ident) => {{
        if $raw_field_values.len() > 1 {
            Err($raw_field_values[1].span)?;
        }

        let RawFieldValue { value, span } =
            $raw_field_values.into_iter().next().unwrap();

        (value, span)
    }};
}

////////////////////////////////////////////////////////////////////////////////
//// Constants

pub const STANDARD: ParseOptions = ParseOptions {
    // skip_invalid_char: false,
    // quote_anychar: true,
    // strict_space: true,
    ignore_mutiline_singleton_value: true,
};

const HTAB: u8 = CharacterTabulation.to_u8();
const SP: u8 = Space.to_u8();
// 13
const CR: u8 = b'\n';
// 10
const LF: u8 = b'\r';
const DQUOTE: u8 = b'"';
const CRLF: &[u8] = b"\n\r";
const LPAREN: u8 = b'(';
const RPAREN: u8 = b')';
const BACKSLASH: u8 = b'\\';
const COMMA: u8 = b',';
const DOT: u8 = FullStop.to_u8();


trait LiftFieldValue<'a>: Sized {
    fn common_split_list_field_value(
        filed_values: Vec<RawFieldValue<'a>>,
    ) -> Result<Vec<RawFieldValue<'a>>, Span> {
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
            let RawFieldValue { value, span } = field_value;

            let mut ep = 0; // end point

            for (i, b) in value.iter().cloned().enumerate() {
                state = match (state, b) {
                    (Normal, DQUOTE) => InStr,
                    (Normal, LPAREN) => InComment(1),
                    (Normal, COMMA) => {
                        members.push(RawFieldValue {
                            value: value.as_slice_cow(ep..i),
                            span,
                        });
                        ep = i;
                        state
                    }
                    (Normal, _) => state,
                    (InStr, QDTEXT![]) => state,
                    (InComment(..), CTEXT![]) => state,
                    (InStr | InComment(..), BACKSLASH) => {
                        Quoting(match state {
                            InStr => Str,
                            InComment(cnt) => Comment(cnt),
                            _ => unreachable!(),
                        })
                    }
                    (Quoting(env), WS![] | VCHAR![] | OBS_TEXT![]) => {
                        match env {
                            Str => InStr,
                            Comment(cnt) => InComment(cnt),
                        }
                    }
                    (InStr, DQUOTE) => Normal,
                    (InComment(cnt), RPAREN) => {
                        if cnt > 0 {
                            InComment(cnt - 1)
                        }
                        else {
                            Normal
                        }
                    }
                    _ => Err(span)?,
                }
            }
        }

        Ok(members)
    }

    fn lift(raw_field_values: Vec<RawFieldValue<'a>>) -> Result<Self, Span>;
}


////////////////////////////////////////////////////////////////////////////////
//// Structures

pub struct ParseOptions {
    // skip_invalid_char: bool,
    // strict_space: bool,
    pub ignore_mutiline_singleton_value: bool,
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
    RequestLackHostField,
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

type RawFields<'a> = HashMap<FlatCow<'a, str>, Vec<RawFieldValue<'a>>>;

#[derive(Debug, Clone)]
struct RawFieldValue<'a> {
    value: FlatCow<'a, ByteStr>,
    span: Span,
}

////////////////////////////////////////////////////////////////////////////////
//// Implementations

impl<'a> LiftFieldValue<'a> for Host {
    fn lift(raw_field_values: Vec<RawFieldValue<'a>>) -> Result<Self, Span> {
        let (value, span) = require_singleton_value!(raw_field_values);

        let s = std::str::from_utf8(&value[..]).map_err(|_| span)?;

        s.parse().map_err(|_| span)
    }
}

impl<'a> LiftFieldValue<'a> for AcceptCharset {
    fn lift(raw_field_values: Vec<RawFieldValue<'a>>) -> Result<Self, Span> {
        let _members = Self::common_split_list_field_value(raw_field_values)?;

        todo!()
    }
}

impl<'a> LiftFieldValue<'a> for Accept {
    fn lift(raw_field_values: Vec<RawFieldValue<'a>>) -> Result<Self, Span> {
        let members = Self::common_split_list_field_value(raw_field_values)?;

        let values = members
            .into_iter()
            .map(|member| {
                let RawFieldValue { mut value, span } = member;

                let (media_range, range_type_offset) =
                    mime::MediaRangeType::consume_bytes_into(&value)
                        .map_err(|_| span)?;

                value = value.as_slice_cow(range_type_offset..);

                let (parameters, parameters_offset) =
                    Parameters::consume_bytes_into(&value)
                        .map_err(|_| span)?;

                let weight = consume_maybe_weight(&value[parameters_offset..])
                    .map_err(|_| span)?
                    .map(|x| x.0)
                    .unwrap_or(1.0);

                Ok::<(MediaRange, f32), Span>((
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
    fn lift(raw_field_values: Vec<RawFieldValue<'a>>) -> Result<Self, Span> {
        let (value, span) = require_singleton_value!(raw_field_values);

        let s = std::str::from_utf8(&value[..]).map_err(|_| span)?;

        if s.trim().to_ascii_lowercase() == "close" {
            Ok(Self)
        }
        else {
            Err(span)
        }
    }
}

impl ConsumeBytesInto for mime::MediaRangeType {
    type Err = ();

    fn consume_bytes_into(
        bytes: &ByteStr,
    ) -> Result<(Self, usize), Self::Err> {
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
        let type_nstring = safe_decode_str!(&bytes[..dpos]).to_lowercase();
        let subtype_nstring =
            safe_decode_str!(&bytes[dpos + 1..epos]).to_lowercase();

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

impl ConsumeBytesInto for Server {
    type Err = ();

    fn consume_bytes_into(
        bytes: &ByteStr,
    ) -> Result<(Self, usize), Self::Err> {
        let mut i = 0;

        let (product, product_offset) = Product::consume_bytes_into(bytes)?;
        i += product_offset;

        let mut rem = vec![];

        while i < bytes.len() {
            let ws_offset = consume_ws(&bytes[i..]);

            if ws_offset == 0 || i + ws_offset == bytes.len() {
                Err(())?;
            }

            i += ws_offset;

            if bytes[i] == LPAREN {
                let (comment, comment_offset) =
                    consume_comment(bytes[i..].into())?;

                i += comment_offset;

                rem.push(ProductOrComment::Comment(comment.into_owned()));
            }
            else {
                let (product_next, product_next_offset) =
                    Product::consume_bytes_into(bytes[i..].into())?;

                i += product_next_offset;

                rem.push(ProductOrComment::Product(product_next));
            }
        }

        Ok((Self { product, rem }, i))
    }
}

impl<'o> ConsumeBytesInto for Product {
    type Err = ();

    fn consume_bytes_into(
        bytes: &ByteStr,
    ) -> Result<(Self, usize), Self::Err> {
        let mut i = 0;

        let (name, name_offset) = consume_token(&bytes.into())?;
        i += name_offset;

        let version = if bytes[i] == b'/' {
            i += 1;
            let (version, version_offset) = consume_token(&bytes[i..].into())?;

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

impl ConsumeBytesInto for MediaType {
    type Err = ();

    fn consume_bytes_into(
        bytes: &ByteStr,
    ) -> Result<(Self, usize), Self::Err> {
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

        let mime =
            match safe_decode_str!(&bytes[..dpos]).to_lowercase().as_str() {
                "application" => unimplemented!(),
                "text" => mime::MediaType::Text(
                    safe_decode_str!(&bytes[dpos + 1..epos])
                        .parse()
                        .map_err(|_| ())?,
                ),
                "audio" | "font" | "haptics" | "image" | "message"
                | "model" | "multipart" | "video" => unimplemented!(),
                _ => throw!(),
            };

        let (parameters, p_offset) =
            Parameters::consume_bytes_into(&bytes[epos..]).map_err(|_| ())?;

        Ok((Self { mime, parameters }, epos + p_offset))
    }
}

impl<'a> LiftFieldValue<'a> for MediaType {
    fn lift(
        mut raw_field_value: Vec<RawFieldValue<'a>>,
    ) -> Result<Self, Span> {
        let RawFieldValue { value, span } = raw_field_value.remove(0);

        let media_type = Self::from_bytes_into(&value).map_err(|_| span)?;

        Ok(media_type)
    }
}

impl ConsumeBytesInto for Parameters {
    type Err = ();

    fn consume_bytes_into(
        bytes: &ByteStr,
    ) -> Result<(Self, usize), Self::Err> {
        use State::*;

        use super::ParameterValue::*;

        macro_rules! throw {
            () => {
                Err(())?
            };
        }

        #[derive(Clone, Copy)]
        enum State {
            Start,
            InPreOWS,
            InPostOWS,
        }

        let mut raw_parameters: HashMap<_, ParameterValue> = HashMap::new();

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
                        consume_token(&bytes[i..].into())?;
                    i += offset;

                    // disjoin with optional weight
                    if param_name == "q" {
                        i = pre_i;
                        break;
                    }

                    if i == bytes.len() {
                        throw!()
                    }

                    let (param_value, offset) = if bytes[i] == DQUOTE {
                        let (qstr, offset) = consume_qstr(&bytes[i..].into())?;

                        (QStr(qstr.into_owned()), offset)
                    }
                    else {
                        let (token, offset) =
                            consume_token(&bytes[i..].into())?;

                        (Token(token.into_owned()), offset)
                    };

                    i += offset;

                    raw_parameters.insert(param_name.into_owned(), param_value);

                    InPreOWS
                }
                _ => throw!(),
            };
        }

        Ok((
            Parameters {
                value: raw_parameters,
            },
            i,
        ))
    }
}

impl<'a> Deref for RawFieldValue<'a> {
    type Target = FlatCow<'a, ByteStr>;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl Error for ParseError {}

impl FromStr for Server {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = s.as_bytes();

        let server = Server::from_bytes_into(ByteStr::new(bytes))?;

        Ok(server)
    }
}

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
    pub fn parse(
        &self,
        bytes: &FlatCow<ByteStr>,
    ) -> Result<MessageHeader, ParseError> {
        /* parse startline */

        let (startline, offset_startline) = self.parse_startline(&bytes)?;

        /* parse fields */

        let (raw_fields, offset_fields) = self
            .parse_raw_fields(&bytes.as_slice_cow(offset_startline..))
            .map_err(|mut err| {
                err.span >>= offset_startline;
                err
            })?;

        let fields = self.lift_fields(raw_fields)?;

        if matches!(startline, StartLine::RequestLine { .. })
            && fields.host().is_none()
        {
            Err(ParseError {
                reason: ParseErrorReason::RequestLackHostField,
                span: (offset_startline..offset_startline + offset_fields)
                    .into(),
            })?
        }

        Ok(match startline {
            StartLine::RequestLine {
                method,
                target,
                version,
            } => MessageHeader::RequestHeader(RequestHeader {
                method,
                target,
                version,
                fields,
            }),
            StartLine::StatusLine {
                version,
                status,
                reason,
            } => MessageHeader::ResponseHeader(ResponseHeader {
                version,
                status,
                reason,
                fields,
            }),
        })
    }

    fn parse_raw_fields<'a>(
        &self,
        bytes: &FlatCow<'a, ByteStr>,
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

                let value = bytes.as_slice_cow(i..j);
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

            let field_name =
                consume!(TCHAR![], b':', throw).try_into().unwrap();

            /* consume `:` */

            i += 1;

            /* consume option white spaces */

            consume!(WS![], _);

            /* parse field value */

            let field_value_start = i;

            let mut field_value = consume!(FIELD_VCHAR![], CR, throw);

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
                        consume!(WS![], _);

                        field_value.to_mut().push(SP);
                        field_value.to_mut().push_str(
                            &consume!(FIELD_VCHAR![], CR, throw),
                        );

                        consume!(CR, LF, throw);
                    }
                    #[allow(unreachable_patterns)]
                    CR | FIELD_VCHAR![] => {
                        /* push field */

                        let field_value_end = i;

                        let field_value = RawFieldValue {
                            value: field_value,
                            span: (field_value_start..field_value_end).into(),
                        };

                        match fields.entry(field_name) {
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

    fn lift_fields(
        &self,
        raw_fields: RawFields,
    ) -> Result<Fields, ParseError> {
        let mut fields = Vec::new();

        for (raw_field_name, raw_field_value) in raw_fields.into_iter() {
            let field_name = raw_field_name.parse::<FieldName>().unwrap();

            debug_assert!(!raw_field_value.is_empty());

            macro_rules! or_else {
                ($e:expr) => {
                    $e.map_err(|span| ParseError {
                        reason: InvalidFieldLine(field_name.clone()),
                        span,
                    })
                };
            }

            let field_value = match &field_name {
                FieldName::Connection => {
                    or_else!(Connection::lift(raw_field_value))?;

                    Field::Connection
                }
                FieldName::Host => {
                    Field::Host(or_else!(Host::lift(raw_field_value))?)
                }
                FieldName::ContentType => Field::ContentType(or_else!(
                    MediaType::lift(raw_field_value)
                )?),
                FieldName::NonStandard(..) => Field::NonStandard(RawField {
                    name: raw_field_name.into_owned(),
                    value: raw_field_value
                        .into_iter()
                        .map(|RawFieldValue { value, .. }| value.into_owned())
                        .collect::<Vec<_>>(),
                }),
                _ => todo!(),
            };

            fields.push(field_value);
        }

        Ok(Fields { fields })
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
                    consume!(s = b"ptions");

                    Request {
                        method: Method::Options,
                    }
                }
                (Start, b'G') => {
                    consume!(s = b"et");

                    Request {
                        method: Method::Get,
                    }
                }
                (Start, b'P') => {
                    i += 1;

                    P
                }
                (Start, b'D') => {
                    consume!(s = b"elete");

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

                    let reason = consume!(@MaybeBoxedStr offset!(=CR)).value;

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

impl MessageHeader {
    pub fn parse(bytes: &ByteStr) -> Result<Self, ParseError> {
        STANDARD.parse(&FlatCow::<ByteStr>::borrow_new(bytes.into()))
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
        OutStr => Ok((buf.to_cow(), i)),
        _ => Err(()),
    }
}

/// return (str, offset)
fn consume_token<'a>(
    bytes: &FlatCow<'a, ByteStr>,
) -> Result<(FlatCow<'a, str>, usize), ()> {
    let mut i = 0;

    while i < bytes.len() {
        match bytes[i] {
            TCHAR![] => (),
            _ => break,
        }

        i += 1;
    }

    Ok((bytes.as_slice_cow(..i).try_into().unwrap(), i))
}

fn consume_maybe_weight(bytes: &[u8]) -> Result<Option<(f32, usize)>, ()> {
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

    Ok(Some(if j < bytes.len() && bytes[j] == DOT {
        if b == b'0' {
            while (j - i) <= 3 {
                match bytes[j] {
                    b'0'..=b'9' => (),
                    _ => break,
                }

                j += 1;
            }

            (
                safe_decode_str!(&bytes[i..j])
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

fn consume_ws(bytes: &[u8]) -> usize {
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

    for b in bytes.iter().cloned() {
        if escaping {
            match b {
                WS![] | VCHAR![] | OBS_TEXT![] => buf.push(b),
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
                    buf.clone_push(b);
                }
                CTEXT![] => {
                    if cnt == 0 {
                        Err(())?
                    }
                }
                _ => Err(())?,
            }
        }

        i += 1;
    }

    Ok((buf.to_cow(), i))
}
