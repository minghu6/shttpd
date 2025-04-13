use derive_more::derive::Display;
use strum::EnumString;



///
/// case-insensitively
///
/// [Character Sets](https://www.iana.org/assignments/character-sets/character-sets.xhtml)
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, EnumString, Display,
)]
pub enum Charset {
    #[strum(serialize = "utf-8", ascii_case_insensitive)]
    UTF8 = 106,
    #[strum(serialize = "gbk", ascii_case_insensitive)]
    GBK = 113,
    #[strum(serialize = "gb18030", ascii_case_insensitive)]
    GB18030 = 114
}
