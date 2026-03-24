//! API for yeet

mod httpsig;
mod key;
mod secret;

mod routes {
    pub mod host;
    pub mod key;
    pub mod osquery;
    pub mod secret;
    pub mod system;
    pub mod verify;
}

pub use httpsig::*;
pub use key::*;
pub use routes::{host::*, key::*, osquery::*, secret::*, system::*, verify::*};
pub use secret::*;

pub type StorePath = String;

#[inline]
pub fn hash(value: impl std::hash::Hash) -> u64 {
    ahash::RandomState::with_seeds(1, 2, 3, 4).hash_one(value)
}

#[inline]
pub fn hash_hex(value: impl std::hash::Hash) -> String {
    format!("{:x}", hash(value))
}
