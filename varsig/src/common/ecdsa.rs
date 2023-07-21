use super::{CommonError, EIP191_ENCODING, KECCAK256, SHA256, SHA512};
use crate::{DeserError, SerError, VarSigTrait};
use std::io::{Read, Write};
use unsigned_varint::{
    encode::{u64 as write_u64, u64_buffer},
    io::read_u64,
};

pub const P256: u16 = 0x1200;
pub const K256: u16 = 0xe7;
pub const P521: u16 = 0x1202;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ecdsa<const HEADER: u64, const HASH: u64, const LEN: usize, const ENCODING: u64> {
    bytes: [u8; LEN],
}

impl<const HEADER: u64, const HASH: u64, const LEN: usize, const ENCODING: u64>
    Ecdsa<HEADER, HASH, LEN, ENCODING>
{
    pub fn new(bytes: [u8; LEN]) -> Self {
        Self { bytes }
    }
    pub fn bytes(&self) -> &[u8; LEN] {
        &self.bytes
    }
    pub fn into_inner(self) -> [u8; LEN] {
        self.bytes
    }
}

pub type Es256<const ENCODING: u64> = Ecdsa<{ P256 as u64 }, { SHA256 as u64 }, 64, ENCODING>;
pub type Es256K<const ENCODING: u64> = Ecdsa<{ K256 as u64 }, { SHA256 as u64 }, 64, ENCODING>;
pub type Es512<const ENCODING: u64> = Ecdsa<{ P521 as u64 }, { SHA512 as u64 }, 128, ENCODING>;
pub type Ethereum<const ENCODING: u64> = Ecdsa<{ K256 as u64 }, { KECCAK256 as u64 }, 65, ENCODING>;
pub type Eip191 = Ethereum<EIP191_ENCODING>;

pub type EcdsaError<const HASH: u64, const ENCODING: u64> = CommonError<HASH, ENCODING>;

impl<const HEADER: u64, const HASH: u64, const LEN: usize, const ENCODING: u64> VarSigTrait
    for Ecdsa<HEADER, HASH, LEN, ENCODING>
{
    type SerError = std::convert::Infallible;
    type DeserError = EcdsaError<HASH, ENCODING>;

    fn valid_header(bytes: &[u8]) -> bool {
        let mut buf = u64_buffer();
        let h = write_u64(HEADER, &mut buf);
        Some(h) == bytes.get(..h.len())
    }

    fn from_reader<R>(mut reader: R) -> Result<Self, DeserError<Self::DeserError>>
    where
        Self: Sized,
        R: Read,
    {
        let header = read_u64(reader.by_ref())?;
        if header != HEADER {
            return Err(DeserError::InvalidHeader);
        };

        let hash = read_u64(reader.by_ref())?;
        if hash != HASH {
            return Err(DeserError::Format(EcdsaError::IncorrectHash(hash)));
        };

        let encoding = read_u64(reader.by_ref())?;
        if encoding != ENCODING {
            return Err(DeserError::Format(EcdsaError::IncorrectEncoding(encoding)));
        };

        let mut bytes = [0u8; LEN];
        reader.read_exact(&mut bytes)?;
        Ok(Self { bytes })
    }

    fn to_writer<W>(&self, mut writer: W) -> Result<(), SerError<Self::SerError>>
    where
        W: Write,
    {
        let mut buf = u64_buffer();
        writer.write_all(write_u64(HEADER, &mut buf))?;
        writer.write_all(write_u64(HASH, &mut buf))?;
        writer.write_all(write_u64(ENCODING, &mut buf))?;
        writer.write_all(&self.bytes)?;
        Ok(())
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, DeserError<Self::DeserError>>
    where
        Self: Sized,
    {
        let mut reader = std::io::Cursor::new(bytes);
        Self::from_reader(&mut reader)
    }
}
