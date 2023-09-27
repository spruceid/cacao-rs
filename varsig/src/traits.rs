use std::io::{Read, Write};

pub trait VarSigTrait {
    type SerError: std::error::Error + std::fmt::Debug;
    type DeserError: std::error::Error + std::fmt::Debug;

    fn valid_header(bytes: &[u8]) -> bool;

    fn from_reader<R>(reader: R) -> Result<Self, DeserError<Self::DeserError>>
    where
        Self: Sized,
        R: Read;

    fn to_writer<W>(&self, writer: W) -> Result<(), SerError<Self::SerError>>
    where
        W: Write;

    fn to_vec(&self) -> Result<Vec<u8>, SerError<Self::SerError>> {
        let mut buf = Vec::new();
        self.to_writer(&mut buf)?;
        Ok(buf)
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, DeserError<Self::DeserError>>
    where
        Self: Sized,
    {
        if !Self::valid_header(bytes) {
            return Err(DeserError::InvalidHeader);
        };
        let mut reader = std::io::Cursor::new(bytes);
        Self::from_reader(&mut reader)
    }
}

#[derive(thiserror::Error, Debug)]
pub enum DeserError<E> {
    #[error("Invalid header")]
    InvalidHeader,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Format(E),
}

#[derive(thiserror::Error, Debug)]
pub enum SerError<E> {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Format(E),
}

impl<E> From<unsigned_varint::io::ReadError> for DeserError<E>
where
    E: From<unsigned_varint::decode::Error>,
{
    fn from(e: unsigned_varint::io::ReadError) -> Self {
        match e {
            unsigned_varint::io::ReadError::Io(e) => DeserError::Io(e),
            unsigned_varint::io::ReadError::Decode(e) => DeserError::Format(e.into()),
            _ => DeserError::Io(e.into()),
        }
    }
}
