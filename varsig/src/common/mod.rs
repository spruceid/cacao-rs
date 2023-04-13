mod ecdsa;
mod ed25519;
mod rsa;

const SHA256: u16 = 0x12;
const SHA512: u16 = 0x13;
const KECCAK256: u16 = 0x1B;

pub use ecdsa::{EcdsaError, Eip191, Es256, Es256K, Es512};
pub use ed25519::{Ed25519, Ed25519Error};
pub use rsa::{Rsa256, Rsa512, RsaError};

#[derive(thiserror::Error, Debug)]
pub enum CommonError {
    #[error(transparent)]
    Varint(#[from] unsigned_varint::decode::Error),
    #[error("Incorrect hash code, expected {0:x}, got {1:x}")]
    IncorrectHash(u64, u64),
}
