
use strum::{ EnumString, Display };

////////////////////////////////////////////////////////////////////////////////
//// Structures

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Display)]
pub enum MediaRangeType {
    StarStar,
    TypeStar(MediaTopType),
    TypeSubType(MediaType)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Display)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Display)]
pub enum MediaRangeSubType {

}

/// Refer [IANA](https://www.iana.org/assignments/media-types/media-types.xhtml)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Display)]
pub enum MediaType {
    Application,
    Audio,
    Font,
    Haptics,
    Image,
    #[strum(to_string = "message/{0}")]
    Message(MessageType),
    Model,
    Multipart,
    #[strum(to_string = "text/{0}")]
    Text(TextType),
    Video,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, EnumString, Display)]
#[strum(ascii_case_insensitive)]
#[non_exhaustive]
pub enum TextType {
    /// Plain text.
    Plain,
    /// HTML text.
    Html,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, EnumString, Display)]
#[strum(ascii_case_insensitive)]
#[non_exhaustive]
/// Represents the type of a message.
pub enum MessageType {
    HTTP
}

////////////////////////////////////////////////////////////////////////////////
//// Implementations

