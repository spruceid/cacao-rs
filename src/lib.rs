use async_trait::async_trait;
use chrono::{DateTime, Utc};
use http::uri::Authority;
use iri_string::types::{UriAbsoluteString, UriString};
pub use siwe::TimeStamp;
use thiserror::Error;

pub mod generic;

pub mod siwe_cacao;

pub struct CACAO<S>
where
    S: SignatureScheme,
{
    h: Header,
    p: Payload,
    s: S::Signature,
}

impl<S> CACAO<S>
where
    S: SignatureScheme,
{
    pub fn new(p: Payload, s: S::Signature) -> Self {
        Self {
            h: S::header(),
            p,
            s,
        }
    }

    pub fn header(&self) -> &Header {
        &self.h
    }

    pub fn payload(&self) -> &Payload {
        &self.p
    }

    pub fn signature(&self) -> &S::Signature {
        &self.s
    }

    pub async fn verify(&self) -> Result<(), VerificationError>
    where
        S: Send + Sync,
        S::Signature: Send + Sync,
    {
        S::verify_cacao(&self).await
    }
}

pub struct Header {
    t: String,
}

impl Header {
    pub fn t<'a>(&'a self) -> &'a str {
        &self.t.as_str()
    }
}

#[async_trait]
pub trait SignatureScheme {
    type Signature;
    fn id() -> String;
    fn header() -> Header {
        Header { t: Self::id() }
    }
    async fn verify(payload: &Payload, sig: &Self::Signature) -> Result<(), VerificationError>
    where
        Self::Signature: Send + Sync;

    async fn verify_cacao(cacao: &CACAO<Self>) -> Result<(), VerificationError>
    where
        Self: Sized,
        Self::Signature: Send + Sync,
    {
        Self::verify(cacao.payload(), cacao.signature()).await
    }
}

#[derive(Error, Debug)]
pub enum VerificationError {
    #[error("Verification Failed")]
    Crypto,
    #[error("Normalisation of verification input failed")]
    Serialization,
    #[error("Missing Payload Verification Material")]
    MissingVerificationMaterial,
    #[error("Not Currently Valid")]
    NotCurrentlyValid,
}

pub struct BasicSignature<S: AsRef<[u8]> + TryFrom<Vec<u8>>> {
    pub s: S,
}

impl<S: AsRef<[u8]> + TryFrom<Vec<u8>>> AsRef<[u8]> for BasicSignature<S> {
    fn as_ref(&self) -> &[u8] {
        self.s.as_ref()
    }
}

impl<S: AsRef<[u8]> + TryFrom<Vec<u8>>> TryFrom<Vec<u8>> for BasicSignature<S> {
    type Error = <S as TryFrom<Vec<u8>>>::Error;
    fn try_from(s: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(Self { s: s.try_into()? })
    }
}

#[derive(Copy, Clone)]
pub enum Version {
    V1 = 1,
}

#[derive(Clone)]
pub struct Payload {
    pub domain: Authority,
    pub iss: UriAbsoluteString,
    pub statement: Option<String>,
    pub aud: UriString,
    pub version: Version,
    pub nonce: String,
    pub iat: TimeStamp,
    pub exp: Option<TimeStamp>,
    pub nbf: Option<TimeStamp>,
    pub request_id: Option<String>,
    pub resources: Vec<UriString>,
}

impl Payload {
    pub fn sign<S: SignatureScheme>(self, s: S::Signature) -> CACAO<S> {
        CACAO {
            h: S::header(),
            p: self,
            s,
        }
    }

    pub async fn verify<S: SignatureScheme>(
        &self,
        s: &<S as SignatureScheme>::Signature,
    ) -> Result<(), VerificationError>
    where
        S: Send + Sync,
        S::Signature: Send + Sync,
    {
        S::verify(&self, s).await
    }

    pub fn iss<'a>(&'a self) -> &'a str {
        &self.iss.as_str()
    }

    pub fn valid_at(&self, t: &DateTime<Utc>) -> bool {
        self.nbf.as_ref().map(|nbf| nbf < t).unwrap_or(true)
            && self.exp.as_ref().map(|exp| exp >= t).unwrap_or(true)
    }

    pub fn valid_now(&self) -> bool {
        self.valid_at(&Utc::now())
    }
}
