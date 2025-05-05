

use strum::{ EnumString, Display };

////////////////////////////////////////////////////////////////////////////////
//// Structures

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Display)]
pub enum MediaRangeType {
    StarStar,
    TypeStar(MediaTopType),
    TypeSubType(MediaType)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Display, EnumString)]
#[strum(ascii_case_insensitive)]
pub enum MediaTopType {
    Application,
    Audio,
    Font,
    Haptics,
    Image,
    Message,
    Model,
    Multipart,
    Text,
    Video,
}

/// Refer [IANA](https://www.iana.org/assignments/media-types/media-types.xhtml)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Display)]
#[strum(ascii_case_insensitive, serialize_all = "lowercase")]
pub enum MediaType {
    #[strum(to_string = "application/{0}")]
    Application(ApplicationType),
    Audio,
    Font,
    Haptics,
    Image,
    #[strum(to_string = "message/{0}")]
    Message(MessageType),
    Model,
    #[strum(to_string = "multipart/{0}")]
    Multipart(MultipartType),
    #[strum(to_string = "text/{0}")]
    Text(TextType),
    Video,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, EnumString, Display)]
#[strum(ascii_case_insensitive, serialize_all = "lowercase")]
#[non_exhaustive]
pub enum ApplicationType {
    JSON,
    XML,
    #[strum(serialize="xhtml+xml")]
    XHTMLAXML,
    OctetStream,
    #[strum(serialize = "x-www-form-urlencoded")]
    XWWWFormUrlencoded
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, EnumString, Display)]
#[strum(ascii_case_insensitive, serialize_all = "lowercase")]
#[non_exhaustive]
pub enum TextType {
    /// Plain text.
    Plain,
    /// HTML text.
    HTML,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, EnumString, Display)]
#[strum(ascii_case_insensitive, serialize_all = "lowercase")]
#[non_exhaustive]
/// Represents the type of a message.
pub enum MultipartType {
    ByteRanges
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, EnumString, Display)]
#[strum(ascii_case_insensitive, serialize_all = "lowercase")]
#[non_exhaustive]
/// Represents the type of a message.
pub enum MessageType {
    HTTP
}

////////////////////////////////////////////////////////////////////////////////
//// Implementations

