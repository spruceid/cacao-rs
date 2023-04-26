use crate::{DeserError, SerError, VarSigTrait};
use std::io::{Read, Write};
use unsigned_varint::{
    decode::Error as VarintError,
    encode::{u64 as write_u64, u64_buffer},
    io::read_u64,
};

pub const ED25519: u16 = 0xed;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ed25519<const ENCODING: u64> {
    bytes: [u8; 64],
}

impl<const ENCODING: u64> Ed25519<ENCODING> {
    pub fn new(bytes: [u8; 64]) -> Self {
        Self { bytes }
    }
    pub fn bytes(&self) -> &[u8; 64] {
        &self.bytes
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Ed25519Error<const ENCODING: u64> {
    #[error(transparent)]
    Varint(#[from] VarintError),
    #[error("Incorrect encoding, expected {:x}, got {0:x}", ENCODING)]
    IncorrectEncoding(u64),
}

impl<const ENCODING: u64> VarSigTrait for Ed25519<ENCODING> {
    type SerError = std::convert::Infallible;
    type DeserError = Ed25519Error<ENCODING>;

    fn valid_header(bytes: &[u8]) -> bool {
        let mut buf = u64_buffer();
        let h = write_u64(ED25519 as u64, &mut buf);
        Some(h) == bytes.get(..2)
    }

    fn from_reader<R>(mut reader: R) -> Result<Self, DeserError<Self::DeserError>>
    where
        Self: Sized,
        R: Read,
    {
        let header = read_u64(reader.by_ref())?;
        if header != ED25519 as u64 {
            return Err(DeserError::InvalidHeader);
        };

        let encoding = read_u64(reader.by_ref())?;
        if encoding != ENCODING {
            return Err(DeserError::Format(Ed25519Error::IncorrectEncoding(
                encoding,
            )));
        }

        let mut bytes = [0u8; 64];
        reader.read_exact(&mut bytes)?;
        Ok(Self { bytes })
    }

    fn to_writer<W>(&self, mut writer: W) -> Result<(), SerError<Self::SerError>>
    where
        W: Write,
    {
        let mut buf = u64_buffer();
        writer.write_all(write_u64(ED25519 as u64, &mut buf))?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::VarSig;

    const EXAMPLE: &[u8] = &[
        0x34, // varsig prefix
        0xed, 0x01, // ed25519 varint encoded header
        0x55, // raw encoding multicodec
        0xae, 0x37, 0x84, 0xf0, 0x3f, 0x9e, 0xe1, 0x16, 0x33, 0x82, 0xfa, 0x6e, 0xfa, 0x73, 0xb0,
        0xc3, 0x1e, 0xcf, 0x58, 0xc8, 0x99, 0xc8, 0x36, 0x70, 0x93, 0x03, 0xba, 0x46, 0x21, 0xd1,
        0xe6, 0xdf, 0x20, 0xe0, 0x9a, 0xaa, 0x56, 0x89, 0x14, 0x29, 0x0b, 0x7e, 0xa1, 0x24, 0xf5,
        0xb3, 0x8e, 0x70, 0xb9, 0xb6, 0x9c, 0x7d, 0xe0, 0xd2, 0x16, 0x88, 0x0e, 0xac, 0x88, 0x5e,
        0xdd, 0x41, 0xc3, 0x02,
    ];

    #[test]
    fn basic_roundtrip_1() {
        let decoded = VarSig::<Ed25519<0x55>>::from_bytes(EXAMPLE).unwrap();
        let encoded = decoded.to_vec().unwrap();

        assert_eq!(EXAMPLE, &encoded[..]);
        assert_eq!(decoded.sig().bytes().as_ref(), &EXAMPLE[4..]);
    }

    #[test]
    fn basic_roundtrip_2() {
        let mut reader = EXAMPLE;
        let decoded = VarSig::<Ed25519<0x55>>::from_reader(&mut reader).unwrap();

        let mut buf = Vec::new();
        decoded.to_writer(&mut buf).unwrap();

        assert_eq!(EXAMPLE, &buf);
        assert_eq!(decoded.sig().bytes().as_ref(), &EXAMPLE[4..]);
    }

    #[test]
    fn enforce_encoding() {
        match VarSig::<Ed25519<0x56>>::from_bytes(EXAMPLE) {
            Err(crate::Error::Format(Ed25519Error::IncorrectEncoding(0x55))) => {}
            _ => panic!("Expected error"),
        };
    }
}
