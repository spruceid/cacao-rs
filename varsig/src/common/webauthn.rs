use super::{JoseError, JoseSig};

pub const WEBAUTHN: u16 = 0x6672;
pub type PasskeySig<const E: u64> = generic::PasskeySig<JoseSig<E>>;
pub type Error<const E: u64> = generic::Error<JoseError<E>>;

pub mod generic {
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

    #[derive(Clone, Debug, PartialEq)]
    pub struct PasskeySig<S> {
        client_data: Vec<u8>,
        authenticator_data: Vec<u8>,
        signature: S,
    }

    impl<S> PasskeySig<S> {
        pub fn new(
            client_data: Vec<u8>,
            authenticator_data: Vec<u8>,
            signature: S,
        ) -> PasskeySig<S> {
            PasskeySig {
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
        pub fn parse_authenticator_data(&self) -> Result<AuthenticatorData, coset::CoseError> {
            AuthenticatorData::from_slice(&self.client_data)
        }
        pub fn signature(&self) -> &S {
            &self.signature
        }
    }

    #[derive(thiserror::Error, Debug)]
    pub enum Error<E: std::error::Error> {
        #[error(transparent)]
        Varint(#[from] unsigned_varint::decode::Error),
        #[error("Invalid Collected Client Data: {0}")]
        InvalidClientData(#[from] serde_json::Error),
        #[error("Invalid Authenticator Data: {0}")]
        InvalidAuthenticatorData(coset::CoseError),
        #[error(transparent)]
        Signature(E),
    }

    impl<E> From<coset::CoseError> for Error<E>
    where
        E: std::error::Error,
    {
        fn from(e: coset::CoseError) -> Self {
            Error::InvalidAuthenticatorData(e)
        }
    }

    impl<S> VarSigTrait for PasskeySig<S>
    where
        S: VarSigTrait,
    {
        type SerError = S::SerError;
        type DeserError = Error<S::DeserError>;

        fn valid_header(bytes: &[u8]) -> bool {
            let mut buf = u64_buffer();
            let h = write_u64(super::WEBAUTHN as u64, &mut buf);
            Some(h) == bytes.get(..2)
        }

        fn from_reader<R>(mut reader: R) -> Result<Self, DeserError<Self::DeserError>>
        where
            R: Read,
        {
            if read_u64(&mut reader)? != super::WEBAUTHN as u64 {
                return Err(DeserError::InvalidHeader);
            };

            let client_data = read_some(&mut reader)?;

            let buf = read_some(&mut reader)?;
            AuthenticatorData::from_slice(&buf).map_err(|e| DeserError::Format(e.into()))?;

            let signature = S::from_reader(&mut reader).map_err(|e| match e {
                DeserError::Format(e) => DeserError::Format(Error::Signature(e)),
                DeserError::Io(e) => DeserError::Io(e),
                DeserError::InvalidHeader => DeserError::InvalidHeader,
            })?;

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

            writer.write_all(write_u64(super::WEBAUTHN as u64, &mut buf))?;
            writer.write_all(write_u64(self.client_data.len() as u64, &mut buf))?;
            writer.write_all(&self.client_data).map_err(SerError::Io)?;

            self.authenticator_data.to_vec();
            writer.write_all(write_u64(self.authenticator_data.len() as u64, &mut buf))?;
            writer
                .write_all(&self.authenticator_data)
                .map_err(SerError::Io)?;

            self.signature.to_writer(&mut writer)?;
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

    fn read_some<R>(reader: &mut R) -> Result<Vec<u8>, unsigned_varint::io::ReadError>
    where
        R: Read,
    {
        let len = read_u64(reader.by_ref())?;
        let mut buf = vec![0; len as usize];
        reader.read_exact(&mut buf)?;
        Ok(buf)
    }
}
