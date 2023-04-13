use crate::{DeserError, SerError, VarSigTrait};
use std::io::{Read, Write};

pub enum EitherSignature<A, B> {
    A(A),
    B(B),
}

#[derive(thiserror::Error, Debug)]
pub enum EitherError<A, B> {
    #[error(transparent)]
    A(A),
    #[error(transparent)]
    B(B),
}

impl<A, B> VarSigTrait for EitherSignature<A, B>
where
    A: VarSigTrait,
    B: VarSigTrait,
{
    type SerError = EitherError<A::SerError, B::SerError>;
    type DeserError = EitherError<A::DeserError, B::DeserError>;
    fn valid_header(bytes: &[u8]) -> bool {
        A::valid_header(bytes) || B::valid_header(bytes)
    }

    fn from_reader<R>(reader: &mut R) -> Result<Self, DeserError<Self::DeserError>>
    where
        R: Read,
        Self: Sized,
    {
        // check the header to discern the sig type
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf)?;

        if A::valid_header(&buf) {
            let chain = &mut buf.chain(reader);
            A::from_reader(chain)
                .map_err(|e| match e {
                    DeserError::Io(e) => DeserError::Io(e),
                    DeserError::InvalidHeader => DeserError::InvalidHeader,
                    DeserError::Format(e) => DeserError::Format(EitherError::A(e)),
                })
                .map(EitherSignature::A)
        } else if B::valid_header(&buf) {
            let chain = &mut buf.chain(reader);
            B::from_reader(chain)
                .map_err(|e| match e {
                    DeserError::Io(e) => DeserError::Io(e),
                    DeserError::InvalidHeader => DeserError::InvalidHeader,
                    DeserError::Format(e) => DeserError::Format(EitherError::B(e)),
                })
                .map(EitherSignature::B)
        } else {
            Err(DeserError::InvalidHeader)
        }
    }

    fn to_writer<W>(&self, writer: &mut W) -> Result<(), SerError<Self::SerError>>
    where
        W: ?Sized + Write,
    {
        match self {
            Self::A(a) => a.to_writer(writer).map_err(|e| match e {
                SerError::Io(e) => SerError::Io(e),
                SerError::Format(e) => SerError::Format(EitherError::A(e)),
            }),
            Self::B(b) => b.to_writer(writer).map_err(|e| match e {
                SerError::Io(e) => SerError::Io(e),
                SerError::Format(e) => SerError::Format(EitherError::B(e)),
            }),
        }
    }
}
