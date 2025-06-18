#![feature(stmt_expr_attributes)]
#![feature(let_chains)]
#![feature(cow_is_borrowed)]
#![feature(iterator_try_collect)]
#![feature(ascii_char_variants)]
#![feature(ascii_char)]
#![feature(trivial_bounds)]
#![feature(impl_trait_in_assoc_type)]
#![feature(anonymous_lifetime_in_impl_trait)]
#![feature(ip_as_octets)]
#![feature(ip_from)]

pub mod datalink;
pub mod network;
pub mod transport;
pub mod application;
pub mod be;
