use derive_more::derive::Display;
use strum::EnumString;



///
/// case-insensitively
///
/// [Character Sets](https://www.iana.org/assignments/character-sets/character-sets.xhtml)
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, EnumString, Display,
)]
#[strum(ascii_case_insensitive)]
pub enum Charset {
    #[strum(serialize = "utf-8")]
    UTF8 = 106,
    #[strum(serialize = "gbk")]
    GBK = 113,
    #[strum(serialize = "gb18030")]
    GB18030 = 114
}
