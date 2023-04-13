use super::{CommonError, KECCAK256, SHA256, SHA512};
use crate::{DeserError, SerError, VarSigTrait};
use std::io::{Read, Write};
use unsigned_varint::{
    encode::{u64 as write_u64, u64_buffer},
    io::read_u64,
};

pub const P256: u16 = 0x1200;
pub const K256: u16 = 0xe7;
pub const P521: u16 = 0x1202;

pub struct Ecdsa<const HEADER: u64, const HASH: u64, const LEN: usize> {
    encoding: u64,
    bytes: [u8; LEN],
}

impl<const HEADER: u64, const HASH: u64, const LEN: usize> Ecdsa<HEADER, HASH, LEN> {
    pub fn new(encoding: u64, bytes: [u8; LEN]) -> Self {
        Self { encoding, bytes }
    }
    pub fn encoding(&self) -> u64 {
        self.encoding
    }
    pub fn bytes(&self) -> &[u8; LEN] {
        &self.bytes
    }
}

pub type Es256 = Ecdsa<{ P256 as u64 }, { SHA256 as u64 }, 64>;
pub type Es256K = Ecdsa<{ K256 as u64 }, { SHA256 as u64 }, 64>;
pub type Es512 = Ecdsa<{ P521 as u64 }, { SHA512 as u64 }, 128>;

pub type Eip191 = Ecdsa<{ K256 as u64 }, { KECCAK256 as u64 }, 65>;

pub type EcdsaError = CommonError;

impl<const HEADER: u64, const HASH: u64, const LEN: usize> VarSigTrait
    for Ecdsa<HEADER, HASH, LEN>
{
    type SerError = std::convert::Infallible;
    type DeserError = EcdsaError;

    fn valid_header(bytes: &[u8]) -> bool {
        let mut buf = u64_buffer();
        let h = write_u64(HEADER, &mut buf);
        Some(h) == bytes.get(..h.len())
    }

    fn from_reader<R>(reader: &mut R) -> Result<Self, DeserError<Self::DeserError>>
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
            return Err(DeserError::Format(EcdsaError::IncorrectHash(HASH, hash)));
        };

        let encoding = read_u64(reader.by_ref())?;
        let mut bytes = [0u8; LEN];
        reader.read_exact(&mut bytes)?;
        Ok(Self { encoding, bytes })
    }

    fn to_writer<W>(&self, writer: &mut W) -> Result<(), SerError<Self::SerError>>
    where
        W: ?Sized + Write,
    {
        let mut buf = u64_buffer();
        writer.write_all(write_u64(HEADER, &mut buf))?;
        writer.write_all(write_u64(HASH, &mut buf))?;
        writer.write_all(write_u64(self.encoding, &mut buf))?;
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
