use std::{borrow::Cow, collections::HashMap};

#[cfg(feature = "parse")]
pub use parsing::*;

pub mod request;
pub mod response;


////////////////////////////////////////////////////////////////////////////////
//// Structures

pub struct Parameters {
    inner: HashMap<Cow<'static, str>, Cow<'static, str>>,
}


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

    use std::{borrow::Cow, ops::AddAssign};

    use ParseErrorReason::*;
    use TokenizeErrorReason::*;
    use m6parsing::*;
    use m6tobytes::{derive_from_bits, derive_to_bits};

    macro_rules! define_token_type {
        ($($name:ident),* $(,)?) => {
            $(
                pub struct $name;

                impl Peek for $name {
                    type TokenType = TokenType;

                    fn token_type() -> Self::TokenType {
                        TokenType::$name
                    }
                }
            )*
        };
    }

    pub struct ParseConfig {
        skip_invalid_char: bool,
        quote_anychar: bool,
    }

    pub struct ParseError {
        pub reason: ParseErrorReason,
        pub span: Span,
    }

    #[derive(Debug)]
    pub enum ParseErrorReason {
        Expect {
            expect: Box<str>,
            found: Box<str>,
            for_: Box<str>,
        },
        TokenizeFailed {
            reason: TokenizeErrorReason,
        },
    }

    pub struct TokenizeError {
        pub reason: TokenizeErrorReason,
        pub span: Span,
    }

    #[derive(Debug)]
    pub enum TokenizeErrorReason {
        UnpairedString,
        InvalidChar(u8),
        /// `\r` without following`\n`
        UncoupledLF,
        /// `\n` without followed by `\r`
        UncoupledCR,
        InvalidCharInStr(u8),
        InvalidQuotedChar(u8),
        DisableMultiLine,
        UnfinishedToken(TokenType),
    }

    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    #[derive_to_bits(u8)]
    #[derive_from_bits(u8)]
    #[repr(u8)]
    pub enum TokenType {
        Text = 1,
        WS,
        Str,
        Comment,
        LParen,
        RParen,
        Comma,
        Slash,
        Colon,
        Semicolon,
        Lt,
        Eq,
        Gt,
        Question,
        At,
        LBracket,
        RBracket,
        BackSlash,
        LBrace,
        RBrace,
        CRLF,
    }

    #[derive(Debug)]
    pub struct Token {
        pub ty: TokenType,
        pub val: Box<[u8]>,
        pub span: Span,
    }

    define_token_type! {
        Text,
        WS,
        Str,
        Comment,
        LParen,
        RParen,
        Comma,
        Slash,
        Colon,
        Semicolon,
        Lt,
        Eq,
        Gt,
        Question,
        At,
        LBracket,
        RBracket,
        BackSlash,
        LBrace,
        RBrace,
        CRLF,
    }

    impl m6parsing::Token for Token {
        type TokenType = TokenType;

        fn token_type(&self) -> Self::TokenType {
            self.ty
        }
    }

    impl Default for ParseConfig {
        fn default() -> Self {
            Self {
                skip_invalid_char: true,
                quote_anychar: true,
            }
        }
    }

    impl ParseConfig {
        fn tokenize(
            &self,
            bytes: &[u8],
        ) -> Result<Box<[Token]>, TokenizeError> {
            use std::ops::Add;

            use State::*;
            use TokenType::*;

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

            /// obs-text, opaque data
            macro_rules! OBS_TEXT {
                () => {
                    0x80..=0xFF
                };
            }

            macro_rules! TCHAR {
                () => {
                    b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' |
                    b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~' |
                    DIGIT![] | ALPHA![] |
                    OBS_TEXT![]
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

            /// `0..=8 | 10..=31 | 127`
            macro_rules! INVALID_CHARS {
                () => {
                    0..=8 | 11..13 | 14..=31 | 127
                };
            }

            /// visable ascii char
            macro_rules! VCHAR {
                () => {
                    0x21..=0x7E
                };
            }

            macro_rules! VALID_QUOTED_CHAR {
                () => {
                    WS![] | VCHAR![] | OBS_TEXT![]
                };
            }

            macro_rules! CTEXT {
                () => {
                    HTAB | SP | 0x21..=0x27 | 0x2A..=0x5B | 0x5D..=0x7E | OBS_TEXT![]
                };
            }

            macro_rules! delimiter2type {
                ($byte:expr) => {
                    match $byte {
                        b'(' => TokenType::LParen,
                        b')' => TokenType::RParen,
                        b',' => TokenType::Comma,
                        b'/' => TokenType::Slash,
                        b':' => TokenType::Colon,
                        b';' => TokenType::Semicolon,
                        b'<' => TokenType::Lt,
                        b'=' => TokenType::Eq,
                        b'>' => TokenType::Gt,
                        b'?' => TokenType::Question,
                        b'@' => TokenType::At,
                        b'[' => TokenType::LBracket,
                        b']' => TokenType::RBracket,
                        b'{' => TokenType::LBrace,
                        b'}' => TokenType::RBrace,
                        _ => unreachable!(),
                    }
                };
            }

            macro_rules! consume {
                (@delimiters $byte:expr) => {
                    (InDelimiter(delimiter2type!($byte)), PUSH)
                };
                (@delimiters($ty:expr) $byte:expr) => {
                    (InDelimiter(delimiter2type!($byte)), PUSH + $ty)
                };
                (@uncoupled_lf($i:ident, $state:ident) $byte:expr) => {{
                    if !self.skip_invalid_char {
                        Err(TokenizeError {
                            reason: UncoupledLF,
                            span: ($i..$i + 1).into(),
                        })?
                    }

                    ($state, NOP)
                }};
                (@uncoupled_cr($i:ident, $state:ident) $byte:expr) => {{
                    if !self.skip_invalid_char {
                        Err(TokenizeError {
                            reason: UncoupledCR,
                            span: ($i..$i + 1).into(),
                        })?
                    }

                    ($state, NOP)
                }};
                (@invalidchars($i:ident, $state:ident) $byte:expr) => {{
                    if !self.skip_invalid_char {
                        Err(TokenizeError {
                            reason: InvalidChar($byte),
                            span: ($i..$i + 1).into(),
                        })?
                    }

                    ($state, NOP)
                }};
                (@disable_multiline($i:ident, $state:ident) $byte:expr) => {{
                    Err(TokenizeError {
                        reason: DisableMultiLine,
                        span: ($i..$i + 1).into(),
                    })?
                }};
            }

            const HTAB: u8 = 0x09;
            const SP: u8 = 0x20;
            // 13
            const CR: u8 = b'\n';
            // 10
            const LF: u8 = b'\r';
            const DQUOTE: u8 = b'"';

            const NOP: StackAction = StackAction(0);
            const PUSH: StackAction = StackAction(1);

            #[derive(Debug, Clone, Copy, PartialEq, Eq)]
            enum State {
                Empty,
                InTChar,
                // nested comment
                InComment(u32),
                InDelimiter(TokenType),
                InCR,
                InCRLF,
                InWS,
                InStr,
                // such as \a
                // prev state
                InQuoting(QuotingEnv),
            }

            #[derive(Debug, Clone, Copy, PartialEq, Eq)]
            enum QuotingEnv {
                InStr,
                InComment(u32),
            }

            /// Buffer Operation
            ///
            /// ```no_main
            /// 0b0000_0000
            ///
            /// ```
            ///
            #[derive(Clone, Copy, PartialEq, Eq)]
            struct StackAction(u16);


            impl Into<State> for QuotingEnv {
                fn into(self) -> State {
                    match self {
                        Self::InStr => InStr,
                        Self::InComment(cnt) => InComment(cnt),
                    }
                }
            }

            impl Add<TokenType> for StackAction {
                type Output = Self;

                fn add(self, rhs: TokenType) -> Self::Output {
                    Self((rhs.to_bits() as u16) << 8 | (self.0 & 0x00FF))
                }
            }

            impl AddAssign<TokenType> for StackAction {
                fn add_assign(&mut self, rhs: TokenType) {
                    *self = self.add(rhs);
                }
            }

            impl StackAction {
                fn part0(&self) -> Self {
                    Self(self.0 & 0x00FF)
                }

                fn part1(&self) -> Option<TokenType> {
                    let bits = (self.0 >> 8) as u8;

                    if bits > 0 {
                        Some(unsafe { TokenType::from_u8(bits) })
                    }
                    else {
                        None
                    }
                }
            }

            fn eval_action(
                action: StackAction,
                byte: u8,
                i: usize,
                buf: &mut Vec<u8>,
                tokens: &mut Vec<Token>,
            ) {
                if PUSH == action.part0() {
                    buf.push(byte);
                }

                if let Some(token_type) = action.part1() {
                    tokens.push(Token {
                        ty: token_type,
                        val: buf.clone().into_boxed_slice(),
                        span: (i - buf.len()..i).into(),
                    });

                    buf.clear();
                }
            }

            let mut state = Empty;

            let mut tokens = Vec::new();
            let mut buf = Vec::new();


            for (i, byte) in bytes.iter().cloned().enumerate() {
                let (next_state, action) = match state {
                    Empty | InDelimiter(..) | InCRLF | InTChar | InWS => {
                        let (next_state, mut next_action) = match byte {
                            TCHAR![] => (InTChar, PUSH),
                            b'(' => (InComment(1), PUSH),
                            DELIMITERS_EX_PAREN![] => {
                                consume!(@delimiters byte)
                            }
                            WS![] => (InWS, PUSH),
                            DQUOTE => (InStr, PUSH),
                            CR => (InCR, PUSH),
                            LF => consume!(
                                @uncoupled_lf(i, state) byte
                            ),
                            b')' | INVALID_CHARS![] => consume!(
                                @invalidchars(i, state) byte
                            ),
                        };

                        match state {
                            InTChar => {
                                if next_state != state {
                                    next_action += Text;
                                }
                            }
                            InWS => {
                                if next_state != state {
                                    next_action += WS;
                                }
                            }
                            InDelimiter(ty) => {
                                next_action += ty;
                            }
                            InCRLF => {
                                next_action += CRLF;
                            }
                            _ => unreachable!(),
                        }

                        (next_state, next_action)
                    }
                    InCR => match byte {
                        LF => (InCRLF, PUSH + CRLF),
                        _ => consume!(
                            @uncoupled_cr(i, state) byte
                        ),
                    },
                    InStr => match byte {
                        b'\\' => (InQuoting(QuotingEnv::InStr), NOP),
                        b'"' => (Empty, PUSH + Str),
                        CR | LF => consume!(
                            @disable_multiline(i, state) byte
                        ),
                        _ => (state, PUSH),
                    },
                    InComment(cnt) => match byte {
                        b')' => {
                            if cnt == 0 {
                                (Empty, PUSH + Comment)
                            }
                            else {
                                (InComment(cnt - 1), PUSH)
                            }
                        }
                        b'(' => (InComment(cnt + 1), PUSH),
                        b'\\' => (InQuoting(QuotingEnv::InComment(cnt)), NOP),
                        CTEXT![] => (state, PUSH),
                        CR | LF => consume!(
                            @disable_multiline(i, state) byte
                        ),
                        _ => consume!(
                                @invalidchars(i, state) byte
                        ),
                    },
                    InQuoting(env) => match byte {
                        VALID_QUOTED_CHAR![] => (env.into(), PUSH),
                        _ => {
                            if self.quote_anychar {
                                (env.into(), PUSH)
                            }
                            else {
                                Err(TokenizeError {
                                    reason: InvalidQuotedChar(byte),
                                    span: (i..i + 1).into(),
                                })?
                            }
                        }
                    },
                };

                eval_action(action, byte, i, &mut buf, &mut tokens);

                state = next_state;
            }

            /* collect tail token */

            let collect_result = match state {
                Empty => Ok(NOP),
                InTChar => Ok(NOP + Text),
                InComment(..) => Err(UnfinishedToken(Comment)),
                InDelimiter(ty) => Ok(NOP + ty),
                InWS => Ok(NOP + WS),
                InCR => Err(UnfinishedToken(CRLF)),
                InCRLF => Ok(NOP + CRLF),
                InStr => Err(UnfinishedToken(Str)),
                InQuoting(env) => Err(UnfinishedToken(match env {
                    QuotingEnv::InStr => Str,
                    QuotingEnv::InComment(..) => Comment,
                })),
            };

            match collect_result {
                Ok(action) => {
                    eval_action(action, 0, bytes.len(), &mut buf, &mut tokens)
                }
                Err(reason) => Err(TokenizeError {
                    reason,
                    span: (bytes.len() - buf.len()..buf.len()).into(),
                })?,
            }

            Ok(tokens.into_boxed_slice())
        }

        fn parse1(
            &self,
            tokens: Box<[Token]>,
        ) -> Result<Box<[(Cow<str>, Vec<Cow<str>>)]>, ParseError> {
            let mut res = Vec::new();


            Ok(res.into_boxed_slice())
        }

        pub fn parse(&self, bytes: &[u8]) -> Result<(), ParseError> {
            let tokens = self.tokenize(bytes).map_err(|err| ParseError {
                reason: TokenizeFailed { reason: err.reason },
                span: err.span,
            })?;

            self.parse1(tokens)?;

            Ok(())
        }
    }
}



////////////////////////////////////////////////////////////////////////////////
//// Implementations

impl Parameters {}
