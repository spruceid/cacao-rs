use crate::{DeserError, SerError, VarSigTrait};
pub use passkey_types::{
    ctap2::AuthenticatorData,
    encoding::{base64url, try_from_base64url},
    webauthn::CollectedClientData,
};
use std::io::{Read, Write};
use unsigned_varint::{
    encode::{u64 as write_u64, u64_buffer},
    io::read_u64,
};

pub const WEBAUTHN: u16 = 0x6672;

#[derive(Clone, Debug, PartialEq)]
pub struct AssertionSigData {
    client_data: Vec<u8>,
    authenticator_data: Vec<u8>,
    signature: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PasskeySig<const ENCODING: u64> {
    assertion: AssertionSigData,
}

impl AssertionSigData {
    pub fn new(
        client_data: Vec<u8>,
        authenticator_data: Vec<u8>,
        signature: Vec<u8>,
    ) -> AssertionSigData {
        AssertionSigData {
            client_data,
            authenticator_data,
            signature,
        }
    }

    pub fn client_data(&self) -> &[u8] {
        &self.client_data
    }
    pub fn parse_client_data(&self) -> Result<CollectedClientData, serde_json::Error> {
        serde_json::from_slice(&self.client_data)
    }
    pub fn authenticator_data(&self) -> &[u8] {
        &self.authenticator_data
    }
    pub fn parse_authenticator_data(&self) -> Result<AuthenticatorData, Error> {
        AuthenticatorData::from_slice(&self.client_data)
            .map_err(|_| Error::InvalidAuthenticatorData)
    }
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }
}

impl<const E: u64> AsRef<AssertionSigData> for PasskeySig<E> {
    fn as_ref(&self) -> &AssertionSigData {
        &self.assertion
    }
}

impl<const E: u64> PasskeySig<E> {
    pub fn new(assertion: AssertionSigData) -> Self {
        Self { assertion }
    }

    pub fn into_inner(self) -> AssertionSigData {
        self.assertion
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Varint(#[from] unsigned_varint::decode::Error),
    #[error("Invalid Collected Client Data")]
    InvalidClientData,
    #[error("Invalid Authenticator Data")]
    InvalidAuthenticatorData,
    #[error("Signature does not match Authenticator Data")]
    SignatureMismatch,
    #[error("Unsupported Cose Algorithm")]
    UnsupportedAlg,
}

#[derive(thiserror::Error, Debug)]
pub enum EncodingErr<const E: u64> {
    #[error(transparent)]
    Other(#[from] Error),
    #[error("Expected {E}, got {0}")]
    Encoding(u64),
}

impl<const E: u64> From<unsigned_varint::decode::Error> for EncodingErr<E> {
    fn from(e: unsigned_varint::decode::Error) -> Self {
        Self::Other(e.into())
    }
}

impl VarSigTrait for AssertionSigData {
    type SerError = std::convert::Infallible;
    type DeserError = Error;

    fn valid_header(bytes: &[u8]) -> bool {
        let mut buf = u64_buffer();
        let h = write_u64(WEBAUTHN as u64, &mut buf);
        Some(h) == bytes.get(..2)
    }

    fn from_reader<R>(mut reader: R) -> Result<Self, DeserError<Self::DeserError>>
    where
        R: Read,
    {
        let client_data = read_some(&mut reader)?;

        let buf = read_some(&mut reader)?;
        AuthenticatorData::from_slice(&buf)
            .map_err(|_| DeserError::Format(Error::InvalidAuthenticatorData))?;

        let signature = read_some(&mut reader)?;

        Ok(Self {
            client_data,
            authenticator_data: buf,
            signature,
        })
    }

    fn to_writer<W>(&self, mut writer: W) -> Result<(), SerError<Self::SerError>>
    where
        W: Write,
    {
        let mut buf = u64_buffer();

        writer.write_all(write_u64(self.client_data.len() as u64, &mut buf))?;
        writer.write_all(&self.client_data).map_err(SerError::Io)?;

        self.authenticator_data.to_vec();
        writer.write_all(write_u64(self.authenticator_data.len() as u64, &mut buf))?;
        writer
            .write_all(&self.authenticator_data)
            .map_err(SerError::Io)?;

        writer.write_all(write_u64(self.signature.len() as u64, &mut buf))?;
        writer.write_all(&self.signature)?;
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

impl<const E: u64> VarSigTrait for PasskeySig<E> {
    type SerError = std::convert::Infallible;
    type DeserError = EncodingErr<E>;

    fn valid_header(bytes: &[u8]) -> bool {
        let mut buf = u64_buffer();
        let h = write_u64(WEBAUTHN as u64, &mut buf);
        Some(h) == bytes.get(..2)
    }

    fn from_reader<R>(mut reader: R) -> Result<Self, DeserError<Self::DeserError>>
    where
        R: Read,
    {
        let encoding = read_u64(&mut reader)?;
        if encoding != E {
            return Err(DeserError::Format(EncodingErr::Encoding(encoding)));
        }

        let assertion = AssertionSigData::from_reader(&mut reader).map_err(|e| match e {
            DeserError::Format(f) => DeserError::Format(EncodingErr::Other(f)),
            DeserError::Io(e) => DeserError::Io(e),
            DeserError::InvalidHeader => DeserError::InvalidHeader,
        })?;
        Ok(Self { assertion })
    }

    fn to_writer<W>(&self, mut writer: W) -> Result<(), SerError<Self::SerError>>
    where
        W: Write,
    {
        let mut buf = u64_buffer();
        writer.write_all(write_u64(E, &mut buf))?;

        self.assertion.to_writer(&mut writer)?;
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

fn read_some<R>(reader: &mut R) -> Result<Vec<u8>, DeserError<Error>>
where
    R: Read,
{
    let len = read_u64(reader.by_ref())?;
    let mut buf = vec![0; len as usize];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}
