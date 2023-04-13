use std::io::{Read, Write};

pub mod common;
pub mod either;
pub mod traits;

pub use either::EitherSignature;
pub use traits::{DeserError, SerError, VarSigTrait};

const VARSIG_VARINT_PREFIX: u8 = 0x34;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VarSig<S: VarSigTrait>(S);

impl<S: VarSigTrait> VarSig<S> {
    pub fn new(s: S) -> Self {
        Self(s)
    }

    pub fn sig(&self) -> &S {
        &self.0
    }

    pub fn from_reader<R>(reader: &mut R) -> Result<Self, Error<S::DeserError>>
    where
        Self: Sized,
        R: Read,
    {
        let mut buf = [0u8; 1];
        reader.read_exact(&mut buf)?;
        if buf[0] != VARSIG_VARINT_PREFIX {
            return Err(Error::InvalidPrefix(buf[0]));
        }
        Ok(Self::new(S::from_reader(reader)?))
    }

    pub fn to_writer<W>(&self, writer: &mut W) -> Result<(), SerError<S::SerError>>
    where
        W: ?Sized + Write,
    {
        writer.write_all(&[VARSIG_VARINT_PREFIX])?;
        self.0.to_writer(writer)
    }

    pub fn to_vec(&self) -> Result<Vec<u8>, SerError<S::SerError>> {
        let mut buf = Vec::new();
        self.to_writer(&mut buf)?;
        Ok(buf)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error<S::DeserError>>
    where
        Self: Sized,
    {
        let mut reader = bytes;
        Self::from_reader(&mut reader)
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error<D> {
    #[error(transparent)]
    Format(D),
    #[error("Invalid Prefix, expected 0x34, got 0x{0:x}")]
    InvalidPrefix(u8),
    #[error("Invalid header")]
    InvalidHeader,
    #[error(transparent)]
    IoError(#[from] std::io::Error),
}

impl<D> From<DeserError<D>> for Error<D> {
    fn from(e: DeserError<D>) -> Self {
        match e {
            DeserError::Format(e) => Error::Format(e),
            DeserError::InvalidHeader => Error::InvalidHeader,
            DeserError::Io(e) => Error::IoError(e),
        }
    }
}
