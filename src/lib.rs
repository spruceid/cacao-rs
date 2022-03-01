use async_trait::async_trait;
use chrono::{DateTime, Utc};
use http::uri::Authority;
use iri_string::types::{UriAbsoluteString, UriString};
use libipld::{
    cbor::DagCborCodec,
    codec::{Decode, Encode},
    DagCbor,
};
use siwe::TimeStamp;
use std::str::FromStr;
use thiserror::Error;

pub mod generic;

// #[cfg(feature = "siwe")]
// pub mod siwe;

#[derive(DagCbor)]
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
    S::Signature: Encode<DagCborCodec> + Decode<DagCborCodec>,
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

#[derive(DagCbor)]
pub struct Header {
    t: String,
}

#[async_trait]
pub trait SignatureScheme {
    type Signature: Encode<DagCborCodec> + Decode<DagCborCodec>;
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

#[derive(DagCbor)]
pub struct BasicSignature<S>
where
    S: Encode<DagCborCodec> + Decode<DagCborCodec>,
{
    pub s: S,
}

#[derive(Copy, Clone)]
pub enum Version {
    V1 = 1,
}

#[derive(Clone)]
pub struct Payload {
    pub domain: Authority,
    pub iss: UriAbsoluteString,
    pub statement: String,
    pub aud: UriAbsoluteString,
    pub version: Version,
    pub nonce: String,
    pub iat: TimeStamp,
    pub exp: Option<TimeStamp>,
    pub nbf: Option<TimeStamp>,
    pub request_id: Option<String>,
    pub resources: Vec<UriString>,
}

#[derive(Clone, DagCbor)]
struct TmpPayload {
    domain: String,
    iss: String,
    statement: String,
    aud: String,
    version: String,
    nonce: String,
    iat: String,
    exp: Option<String>,
    nbf: Option<String>,
    requestId: Option<String>,
    resources: Vec<String>,
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
