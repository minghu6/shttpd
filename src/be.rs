
////////////////////////////////////////////////////////////////////////////////
//// Macros

macro_rules! define_unsigned_be {
    ($( {
        struct_name=$struct_name: ident,
        storage_type=$origin_type: ty

    } ),* $(,)?) => {
        $(
            #[derive(Default, Clone, Copy, Hash, PartialEq, Eq)]
            #[repr(transparent)]
            pub struct $struct_name($origin_type);

            impl $struct_name {
                /// from from_ne
                pub const fn new(x: $origin_type) -> Self {
                    Self::from_ne(x)
                }

                pub const fn from_ne(x: $origin_type) -> Self {
                    Self(x.to_be())
                }

                pub const fn from_le(x: $origin_type) -> Self {
                    Self::new(<$origin_type>::from_le(x))
                }

                pub const fn from_be(x: $origin_type) -> Self {
                    Self::new(<$origin_type>::from_be(x))
                }

                pub const fn to_ne(&self) -> $origin_type {
                    <$origin_type>::from_be(self.0)
                }

                pub const fn to_ne_bytes(&self) -> [u8; std::mem::size_of::<$origin_type>()] {
                    self.to_ne().to_ne_bytes()
                }
            }

            impl std::fmt::Debug for $struct_name {
                fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    write!(f, "{}", self.to_ne())
                }
            }

            impl From<$origin_type> for $struct_name {
                fn from(value: $origin_type) -> Self {
                    Self::new(value)
                }
            }
        )*
    };
}

////////////////////////////////////////////////////////////////////////////////
//// Structures

define_unsigned_be! {
    { struct_name = U16Be, storage_type=u16 },
    { struct_name = U32Be, storage_type=u32 },
    { struct_name = U64Be, storage_type=u64 },
}

