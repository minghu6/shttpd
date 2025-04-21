#![feature(stmt_expr_attributes)]
#![feature(let_chains)]
#![feature(cow_is_borrowed)]
#![feature(iterator_try_collect)]
#![feature(ascii_char_variants)]
#![feature(ascii_char)]
#![feature(trivial_bounds)]
#![feature(impl_trait_in_assoc_type)]

pub mod datalink;
pub mod network;
pub mod transport;
pub mod application;


#[cfg(test)]
mod tests {

}
