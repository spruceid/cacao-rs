use super::{CommonError, SHA256, SHA512};
use crate::{DeserError, SerError, VarSigTrait};
use std::io::{Read, Write};
use unsigned_varint::{
    encode::{u64 as write_u64, u64_buffer},
    io::read_u64,
};

pub const RSA: u16 = 0x1205;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Rsa<const HASH: u64, const ENCODING: u64> {
    bytes: Vec<u8>,
}

impl<const HASH: u64, const ENCODING: u64> Rsa<HASH, ENCODING> {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn into_inner(self) -> Vec<u8> {
        self.bytes
    }
}

pub type Rsa256<const ENCODING: u64> = Rsa<{ SHA256 as u64 }, ENCODING>;
pub type Rsa512<const ENCODING: u64> = Rsa<{ SHA512 as u64 }, ENCODING>;

pub type RsaError<const HASH: u64, const ENCODING: u64> = CommonError<HASH, ENCODING>;

impl<const HASH: u64, const ENCODING: u64> VarSigTrait for Rsa<HASH, ENCODING> {
    type SerError = std::convert::Infallible;
    type DeserError = RsaError<HASH, ENCODING>;

    fn valid_header(bytes: &[u8]) -> bool {
        let mut buf = u64_buffer();
        let h = write_u64(RSA as u64, &mut buf);
        Some(h) == bytes.get(..2)
    }

    fn from_reader<R>(mut reader: R) -> Result<Self, DeserError<Self::DeserError>>
    where
        Self: Sized,
        R: Read,
    {
        let header = read_u64(reader.by_ref())?;
        if header != RSA as u64 {
            return Err(DeserError::InvalidHeader);
        };

        let hash = read_u64(reader.by_ref())?;
        if hash != HASH {
            return Err(DeserError::Format(RsaError::IncorrectHash(hash)));
        };

        let len = read_u64(reader.by_ref())?;
        let mut bytes = Vec::with_capacity(len as usize);

        let encoding = read_u64(reader.by_ref())?;
        if encoding != ENCODING {
            return Err(DeserError::Format(RsaError::IncorrectEncoding(encoding)));
        };
        reader.read_exact(&mut bytes)?;
        Ok(Self { bytes })
    }

    fn to_writer<W>(&self, mut writer: W) -> Result<(), SerError<Self::SerError>>
    where
        W: Write,
    {
        let mut buf = u64_buffer();
        writer.write_all(write_u64(RSA as u64, &mut buf))?;
        writer.write_all(write_u64(HASH, &mut buf))?;
        writer.write_all(write_u64(self.bytes.len() as u64, &mut buf))?;
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
