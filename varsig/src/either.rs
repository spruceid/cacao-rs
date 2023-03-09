use crate::{Error, SignatureHeader};
use std::io::{Error as IoError, Read, Write};

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

impl<A, B> SignatureHeader for EitherSignature<A, B>
where
    A: SignatureHeader,
    B: SignatureHeader,
{
    type SerError = EitherError<A::SerError, B::SerError>;
    type DeserError = EitherError<A::DeserError, B::DeserError>;
    fn from_reader<R>(reader: &mut R) -> Result<Self, Self::DeserError>
    where
        R: Read,
        Self: Sized,
    {
        todo!()
    }

    fn to_writer<W>(&self, writer: &mut W) -> Result<(), Self::SerError>
    where
        W: ?Sized + Write,
    {
        match self {
            Self::A(a) => a.to_writer(writer).map_err(EitherError::A),
            Self::B(b) => b.to_writer(writer).map_err(EitherError::B),
        }
    }
}
