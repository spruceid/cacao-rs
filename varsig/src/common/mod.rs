use crate::{DeserError, SerError, VarSigTrait};
use std::io::{Read, Write};

pub mod ecdsa;
pub mod ed25519;
pub mod rsa;
#[cfg(feature = "webauthn")]
pub mod webauthn;

const SHA256: u16 = 0x12;
const SHA512: u16 = 0x13;
const KECCAK256: u16 = 0x1B;

pub const RAW_ENCODING: u64 = 0x55;
pub const EIP191_ENCODING: u64 = 0xe191;
pub const DAG_JSON_ENCODING: u64 = 0x0129;
pub const DAG_PROTOBUF_ENCODING: u64 = 0x70;
pub const DAG_CBOR_ENCODING: u64 = 0x71;

pub use ecdsa::{EcdsaError, Eip191, Es256, Es256K, Es512, Ethereum};
pub use ed25519::{Ed25519, Ed25519Error};
pub use rsa::{Rsa256, Rsa512, RsaError};

#[cfg(feature = "webauthn")]
pub use webauthn::PasskeySig;

#[derive(thiserror::Error, Debug)]
pub enum JoseError<const ENCODING: u64> {
    #[error(transparent)]
    Varint(#[from] unsigned_varint::decode::Error),
    #[error("Incorrect hash code, expected {0:x}, got {0:x}")]
    IncorrectHash(u64, u64),
    #[error("Incorrect encoding, expected {:x}, got {0:x}", ENCODING)]
    IncorrectEncoding(u64),
}

#[derive(thiserror::Error, Debug)]
pub enum CommonError<const HASH: u64, const ENCODING: u64> {
    #[error(transparent)]
    Varint(#[from] unsigned_varint::decode::Error),
    #[error("Incorrect hash code, expected {:x}, got {0:x}", HASH)]
    IncorrectHash(u64),
    #[error("Incorrect encoding, expected {:x}, got {0:x}", ENCODING)]
    IncorrectEncoding(u64),
}

impl<const H: u64, const E: u64> From<CommonError<H, E>> for JoseError<E> {
    fn from(e: CommonError<H, E>) -> Self {
        match e {
            CommonError::Varint(e) => Self::Varint(e),
            CommonError::IncorrectHash(h) => Self::IncorrectHash(H, h),
            CommonError::IncorrectEncoding(e) => Self::IncorrectEncoding(e),
        }
    }
}

impl<const E: u64> From<Ed25519Error<E>> for JoseError<E> {
    fn from(e: Ed25519Error<E>) -> Self {
        match e {
            Ed25519Error::Varint(e) => Self::Varint(e),
            Ed25519Error::IncorrectEncoding(e) => Self::IncorrectEncoding(e),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum JoseSig<const E: u64> {
    Es256(Es256<E>),
    Es512(Es512<E>),
    Rsa256(Rsa256<E>),
    Rsa512(Rsa512<E>),
    EdDSA(Ed25519<E>),
    Es256K(Es256K<E>),
}

impl<const E: u64> VarSigTrait for JoseSig<E> {
    type SerError = std::convert::Infallible;
    type DeserError = JoseError<E>;

    fn valid_header(bytes: &[u8]) -> bool {
        Es256::<E>::valid_header(bytes)
            || Es512::<E>::valid_header(bytes)
            || Rsa256::<E>::valid_header(bytes)
            || Rsa512::<E>::valid_header(bytes)
            || Ed25519::<E>::valid_header(bytes)
            || Es256K::<E>::valid_header(bytes)
    }

    fn from_reader<R>(mut reader: R) -> Result<Self, DeserError<Self::DeserError>>
    where
        Self: Sized,
        R: Read,
    {
        let mut buf = [0u8; 19];
        reader.read_exact(&mut buf)?;
        if Es256::<E>::valid_header(&buf) {
            Ok(Self::Es256(
                Es256::<E>::from_reader(buf.chain(reader)).map_err(convert_err)?,
            ))
        } else if Es512::<E>::valid_header(&buf) {
            Ok(Self::Es512(
                Es512::<E>::from_reader(buf.chain(reader)).map_err(convert_err)?,
            ))
        } else if Rsa256::<E>::valid_header(&buf) {
            Ok(Self::Rsa256(
                Rsa256::<E>::from_reader(buf.chain(reader)).map_err(convert_err)?,
            ))
        } else if Rsa512::<E>::valid_header(&buf) {
            Ok(Self::Rsa512(
                Rsa512::<E>::from_reader(buf.chain(reader)).map_err(convert_err)?,
            ))
        } else if Ed25519::<E>::valid_header(&buf) {
            Ok(Self::EdDSA(
                Ed25519::<E>::from_reader(buf.chain(reader)).map_err(convert_err)?,
            ))
        } else if Es256K::<E>::valid_header(&buf) {
            Ok(Self::Es256K(
                Es256K::<E>::from_reader(buf.chain(reader)).map_err(convert_err)?,
            ))
        } else {
            Err(DeserError::InvalidHeader)
        }
    }

    fn to_writer<W>(&self, writer: W) -> Result<(), SerError<Self::SerError>>
    where
        W: Write,
    {
        match self {
            Self::Es256(s) => s.to_writer(writer),
            Self::Es512(s) => s.to_writer(writer),
            Self::Rsa256(s) => s.to_writer(writer),
            Self::Rsa512(s) => s.to_writer(writer),
            Self::EdDSA(s) => s.to_writer(writer),
            Self::Es256K(s) => s.to_writer(writer),
        }
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, DeserError<Self::DeserError>>
    where
        Self: Sized,
    {
        let mut reader = std::io::Cursor::new(bytes);
        Self::from_reader(&mut reader)
    }
}

fn convert_err<E1, E2>(e: DeserError<E1>) -> DeserError<E2>
where
    E2: From<E1>,
{
    match e {
        DeserError::Io(e) => DeserError::Io(e),
        DeserError::InvalidHeader => DeserError::InvalidHeader,
        DeserError::Format(e) => DeserError::Format(e.into()),
    }
}
