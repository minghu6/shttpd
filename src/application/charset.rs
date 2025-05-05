use derive_more::derive::Display;
use strum::EnumString;



///
/// case-insensitively
///
/// [Character Sets](https://www.iana.org/assignments/character-sets/character-sets.xhtml)
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, EnumString, Display,
)]
#[strum(ascii_case_insensitive, serialize_all = "lowercase")]
pub enum Charset {
    #[strum(serialize = "utf-8")]
    UTF8 = 106,
    GBK = 113,
    GB18030 = 114
}
