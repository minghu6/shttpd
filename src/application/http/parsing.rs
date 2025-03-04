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
    borrow::{Borrow, Cow},
    collections::{HashMap, hash_map::Entry},
    convert::Infallible,
    error::Error,
    ops::{Deref, Index, RangeBounds},
    str::FromStr,
};

use ParseErrorReason::*;
use derive_more::derive::Display;
use m6parsing::Span;
use m6ptr::{CowBuf, FlatCow};

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

trait ConsumeBytes<'a>: Sized {
    fn consume(bytes: &FlatCow<'a, [u8]>) -> Result<(Self, usize), ()>;
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

type RawFields<'a> = HashMap<&'a str, Vec<RawFieldValue<'a>>>;

#[derive(Debug, Clone)]
struct RawFieldValue<'a> {
    value: FlatCow<'a, [u8]>,
    span: Span,
}

////////////////////////////////////////////////////////////////////////////////
//// Implementations

impl<'a> LiftFieldValue<'a> for AcceptCharset {
    fn lift(raw_field_values: Vec<RawFieldValue<'a>>) -> Result<Self, Span> {
        let _members = Self::common_split_list_field_value(raw_field_values)?;

        todo!()
    }
}

impl<'a> LiftFieldValue<'a> for ContentType<'a> {
    fn lift(raw_field_values: Vec<RawFieldValue<'a>>) -> Result<Self, Span> {
        Ok(Self {
            value: MediaType::lift(raw_field_values)?,
        })
    }
}

impl<'a> LiftFieldValue<'a> for Accept<'a> {
    fn lift(raw_field_values: Vec<RawFieldValue<'a>>) -> Result<Self, Span> {
        let members = Self::common_split_list_field_value(raw_field_values)?;

        let values = members
            .into_iter()
            .map(|member| {
                let RawFieldValue { mut value, span } = member;

                let (media_range, range_type_offset) =
                    mime::MediaRangeType::consume(&value).map_err(|_| span)?;

                value = value.as_slice_cow(range_type_offset..);

                let (parameters, parameters_offset) =
                    consume_parameters(&value).map_err(|_| span)?;

                let weight = consume_maybe_weight(&value[parameters_offset..])
                    .map_err(|_| span)?
                    .map(|x| x.0)
                    .unwrap_or(1.0);

                Ok::<(MediaRange<'_>, f32), Span>((
                    MediaRange {
                        mime: media_range,
                        parameters,
                    },
                    weight,
                ))
            })
            .try_collect::<Vec<(MediaRange<'_>, f32)>>()?;

        Ok(Self { values })
    }
}

impl<'a> ConsumeBytes<'a> for mime::MediaRangeType {
    fn consume(bytes: &FlatCow<'a, [u8]>) -> Result<(Self, usize), ()> {
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

impl<'a> LiftFieldValue<'a> for MediaType<'a> {
    fn lift(
        mut raw_field_value: Vec<RawFieldValue<'a>>,
    ) -> Result<Self, Span> {
        let RawFieldValue { value, span } = raw_field_value.remove(0);

        macro_rules! throw {
            () => {
                Err(span)?
            };
        }

        let Some(dpos) = value.iter().position(|b| *b == b'/')
        else {
            throw!()
        };

        let Some(epos) = value[dpos + 1..].iter().position(|b| match *b {
            TCHAR![] => false,
            _ => true,
        })
        else {
            throw!()
        };

        let mime =
            match safe_decode_str!(&value[..dpos]).to_lowercase().as_str() {
                "application" => unimplemented!(),
                "text" => mime::MediaType::Text(
                    safe_decode_str!(&value[dpos + 1..epos])
                        .parse()
                        .map_err(|_| span)?,
                ),
                "audio" | "font" | "haptics" | "image" | "message"
                | "model" | "multipart" | "video" => unimplemented!(),
                _ => throw!(),
            };

        let (parameters, _parameters_offset) =
            consume_parameters(&value.as_slice_cow(epos..))
                .map_err(|_| span)?;

        Ok(MediaType { mime, parameters })
    }
}

impl<'a> Deref for RawFieldValue<'a> {
    type Target = FlatCow<'a, [u8]>;

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
        &'a self,
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

        let fields = self.lift_fields(raw_fields)?;

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
                fields,
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
                fields,
                body,
            }),
        })
    }

    fn parse_raw_fields<'a>(
        &'a self,
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

            let field_name = safe_decode_str!(consume!(TCHAR![], b':', throw));

            /* consume `:` */

            i += 1;

            /* consume option white spaces */

            consume!(WS![], _);

            /* parse field value */

            let field_value_start = i;

            let mut field_value = FlatCow::<[u8]>::borrow_new(consume!(
                FIELD_VCHAR![],
                CR,
                throw
            ));

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
                            span: (field_value_start..field_value_end).into(),
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
        &'a self,
        raw_fields: RawFields<'a>,
    ) -> Result<Fields<'a>, ParseError> {
        use FieldName::*;

        let mut fields = HashMap::new();

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
                ContentType => Field::ContentType(or_else!(MediaType::lift(
                    raw_field_value
                ))?),
                NonSandard(..) => Field::NonSandard(RawField {
                    name: raw_field_name,
                    value: raw_field_value
                        .into_iter()
                        .map(|RawFieldValue { value, .. }| value)
                        .collect::<Vec<_>>()
                        .into_boxed_slice(),
                }),
                _ => todo!(),
            };

            fields.insert(field_name, field_value);
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

impl<'a> Message<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, ParseError> {
        STANDARD.parse(bytes)
    }
}


////////////////////////////////////////////////////////////////////////////////
//// Functions

pub fn as_slice_cow<'a, T, B, I>(cow: Cow<'a, B>, index: I) -> Cow<'a, B>
where
    T: Borrow<B> + Index<I>,
    B: Index<I, Output = B> + Clone,
    I: RangeBounds<usize>,
{
    match cow {
        Cow::Borrowed(borrowed) => Cow::Borrowed(&borrowed[index]),
        Cow::Owned(owned) => Cow::Owned(owned[index].clone()),
    }
}


///
/// first byte is double-quote
///
/// return (parsed-bytes (exclude double quote), offset)
///
fn consume_qstr<'a>(
    bytes: &FlatCow<'a, [u8]>,
) -> Result<(FlatCow<'a, [u8]>, usize), ()> {
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
    bytes: &FlatCow<'a, [u8]>,
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


#[allow(unused)]
fn consume_field_value_as_singleton<'a>(
    value: FlatCow<'a, [u8]>,
) -> SingletonFieldValue<'a> {
    use QuotingEnv::*;
    use SingletonFieldValue::*;
    use State::*;

    let mut state = Start;
    let mut buf = CowBuf::from(&value);

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
                WS![] | 0x21..=0x27 | 0x2A..=0x5B | 0x5D..=0x7E | OBS_TEXT![],
            ) => state,
            (InStr | InComment(..), BACKSLASH) => Quoting(match state {
                InStr => Str,
                InComment(cnt) => Comment(cnt),
                _ => unreachable!(),
            }),
            (Quoting(env), WS![] | VCHAR![] | OBS_TEXT![]) => match env {
                Str => {
                    buf.clone_push(b);

                    InStr
                }
                Comment(cnt) => InComment(cnt),
            },
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
        InToken => Token({ buf.to_cow().try_into().unwrap() }),
        OutStr => QStr(buf.to_cow()),
        _ => {
            drop(buf);
            Oth(value)
        }
    }
}

fn consume_parameters<'a>(
    bytes: &FlatCow<'a, [u8]>,
) -> Result<(Parameters<'a>, usize), ()> {
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

    let mut raw_parameters: HashMap<_, Vec<ParameterValue<'a>>> =
        HashMap::new();

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
                    consume_token(&bytes.as_slice_cow(i..))?;
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
                    let (qstr, offset) =
                        consume_qstr(&bytes.as_slice_cow(i..))?;

                    (QStr(qstr), offset)
                }
                else {
                    let (token, offset) =
                        consume_token(&bytes.as_slice_cow(i..))?;

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

fn consume_maybe_weight(bytes: &[u8]) -> Result<Option<(f32, usize)>, ()> {
    let mut i = 0;

    /* consume maybe space */

    i += consume_obs(bytes);

    if i < bytes.len() && bytes[i] == Semicolon.to_u8() {
        i += 1;
    }
    else {
        return Ok(None);
    }

    i += consume_obs(bytes);

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

fn consume_obs(bytes: &[u8]) -> usize {
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
