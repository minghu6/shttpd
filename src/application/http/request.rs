use cookie;
use mime::{ Mime, self};

use super::Parameters;

////////////////////////////////////////////////////////////////////////////////
//// Structures

// #[repr(transparent)]
// pub struct Accept {
//     items: Box<[MediaRangeAndWeight]>
// }


// pub struct MediaRangeAndWeight {
//     media_range: Mime,
//     params: Parameters,
//     weight: f32,
// }

pub struct Cookie {
    // 'static lifetimes doen't means there are static storage in binary file.
    // It's just used as Cow<'staitc> in cookie::Cookie, and we choose Cow::Owned.
    items: Box<[cookie::Cookie<'static>]>,
}


////////////////////////////////////////////////////////////////////////////////
//// Implementations

impl Cookie {
    pub fn get(&self, name: &str) -> Option<&cookie::Cookie> {
        self.items.iter().find(|cookie| cookie.name() == name)
    }
}

#[cfg(feature = "parse")]
mod parsing {
    use std::{convert::Infallible, str::FromStr};

    use super::*;

    /// Lossy match, invalid field would be ignored.
    impl FromStr for Cookie {
        type Err = Infallible;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            let mut items = vec![];

            for item_s in s.trim_start().split(";") {
                if let Ok(cookie) =
                    cookie::Cookie::from_str(item_s.trim_start())
                {
                    items.push(cookie);
                }
            }

            Ok(Self {
                items: items.into_boxed_slice(),
            })
        }
    }
}
