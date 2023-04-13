mod ecdsa;
mod ed25519;
mod rsa;

const SHA256: u16 = 0x12;
const SHA512: u16 = 0x13;

pub use ecdsa::{EcdsaError, Es256, Es256K, Es512};
pub use ed25519::{Ed25519, Ed25519Error};
pub use rsa::{Rsa256, Rsa512, RsaError};
