use super::{
    recap_cacao::{
        version::SiweVersion, Error as RecapError, RecapCacao, RecapFacts, RecapSignature,
        RecapVerify,
    },
    ucan_cacao::{Error as UcanError, UcanCacao, UcanSignature},
    webauthn::{Error as WebauthnError, WebauthnCacao, WebauthnSignature, WebauthnVersion},
    CacaoVerifier, Flattener,
};
use async_trait::async_trait;
use libipld::{cid::Cid, Ipld};
use multidid::MultiDid;
use serde::{Deserialize, Serialize};
use siwe::Message;
use ssi_ucan::{
    jose::{self, VerificationError},
    version::SemanticVersion,
    Ucan,
};
use std::collections::BTreeMap;
use ucan_capabilities_object::Capabilities;
use varsig::{VarSig, VarSigTrait};

#[derive(Debug, Clone, PartialEq, Deserialize, Eq, Hash)]
pub struct CommonCacao<U = BTreeMap<String, serde_json::Value>, NB = Ipld, W = U> {
    #[serde(rename = "iss")]
    issuer: MultiDid,
    #[serde(rename = "aud")]
    audience: MultiDid,
    #[serde(rename = "att")]
    attenuations: Capabilities<NB>,
    #[serde(rename = "nnc", skip_serializing_if = "Option::is_none", default)]
    nonce: Option<String>,
    #[serde(rename = "prf", skip_serializing_if = "Option::is_none", default)]
    proof: Option<Vec<Cid>>,
    #[serde(rename = "iat", skip_serializing_if = "Option::is_none", default)]
    issued_at: Option<u64>,
    #[serde(rename = "nbf", skip_serializing_if = "Option::is_none", default)]
    not_before: Option<u64>,
    #[serde(rename = "exp", skip_serializing_if = "Option::is_none", default)]
    expiration: Option<u64>,
    #[serde(flatten)]
    typ: Types<U, W>,
}

impl<U, NB, W> CommonCacao<U, NB, W> {
    pub fn issuer(&self) -> &MultiDid {
        &self.issuer
    }

    pub fn audience(&self) -> &MultiDid {
        &self.audience
    }

    pub fn capabilities(&self) -> &Capabilities<NB> {
        &self.attenuations
    }

    pub fn nonce(&self) -> Option<&str> {
        self.nonce.as_deref()
    }

    pub fn proof(&self) -> Option<&[Cid]> {
        self.proof.as_deref()
    }

    pub fn issued_at(&self) -> Option<u64> {
        self.issued_at
    }

    pub fn not_before(&self) -> Option<u64> {
        self.not_before
    }

    pub fn expiration(&self) -> Option<u64> {
        self.expiration
    }

    pub fn facts(&self) -> Option<Facts<'_, U, W>> {
        self.typ.facts()
    }

    pub fn signature(&self) -> Signature<'_> {
        self.typ.signature()
    }

    pub fn valid_at_time(&self, time: u64, skew: Option<u64>) -> bool {
        self.expiration
            .map_or(true, |exp| time < exp + skew.unwrap_or(0))
            && self
                .not_before
                .map_or(true, |nbf| time >= nbf - skew.unwrap_or(0))
            && self.issued_at.map_or(true, |iat| {
                self.not_before.map_or(true, |nbf| nbf < iat)
                    && self.expiration.map_or(true, |exp| iat < exp)
            })
    }

    pub async fn verify<V>(&self, verifier: &V) -> Result<(), V::Error>
    where
        V: CacaoVerifier<Self>,
        NB: Send + Sync,
    {
        verifier.verify(self).await
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Eq, Hash)]
#[serde(deny_unknown_fields)]
struct Type<V, F, S> {
    #[serde(rename = "v")]
    version: V,
    #[serde(
        rename = "fct",
        skip_serializing_if = "Option::is_none",
        default = "Option::default"
    )]
    facts: Option<Flattener<F>>,
    #[serde(rename = "s", bound = "S: VarSigTrait")]
    signature: VarSig<S>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Eq, Hash)]
#[serde(untagged)]
enum Types<U, W = U> {
    Ucan(Type<SemanticVersion, U, UcanSignature>),
    Recap(Type<SiweVersion, RecapFacts, RecapSignature>),
    Webauthn(Type<WebauthnVersion, W, WebauthnSignature>),
}

impl<U, W> Types<U, W> {
    pub fn facts(&self) -> Option<Facts<'_, U, W>> {
        match self {
            Types::Ucan(ref ucan) => ucan.facts.as_ref().map(|f| Facts::Ucan(&f.f)),
            Types::Recap(ref recap) => recap.facts.as_ref().map(|f| Facts::Recap(&f.f)),
            Types::Webauthn(ref webauthn) => webauthn.facts.as_ref().map(|f| Facts::Webauthn(&f.f)),
        }
    }

    pub fn signature(&self) -> Signature<'_> {
        match self {
            Types::Ucan(ref ucan) => Signature::Ucan(&ucan.signature),
            Types::Recap(ref recap) => Signature::Recap(&recap.signature),
            Types::Webauthn(ref webauthn) => Signature::Webauthn(&webauthn.signature),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(untagged)]
pub enum Facts<'a, U, W = U> {
    Recap(&'a RecapFacts),
    Ucan(&'a U),
    Webauthn(&'a W),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Signature<'a> {
    Recap(&'a VarSig<RecapSignature>),
    Ucan(&'a VarSig<UcanSignature>),
    Webauthn(&'a VarSig<WebauthnSignature>),
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct CommonVerifier<T>(T);

impl<T> CommonVerifier<T> {
    pub fn new(t: T) -> Self {
        Self(t)
    }
}

impl<U, NB, W> CommonCacao<BTreeMap<String, U>, NB, W>
where
    U: Clone + Serialize,
    NB: Clone + Serialize,
    W: Clone,
{
    pub fn serialize_jwt(&self) -> Result<Option<String>, UcanError> {
        Ok(UcanCacao::try_from(self.clone())
            .ok()
            .map(Ucan::from)
            .map(|ucan| ucan.encode())
            .transpose()?)
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error<U: std::error::Error = UcanError, W: std::error::Error = WebauthnError> {
    #[error(transparent)]
    Ucan(U),
    #[error(transparent)]
    Recap(#[from] RecapError),
    #[error(transparent)]
    Webauthn(W),
    #[error("Signature and Facts Mismatch")]
    Mismatch,
}

impl<W: std::error::Error> From<UcanError> for Error<UcanError, W> {
    fn from(e: UcanError) -> Self {
        Self::Ucan(e)
    }
}

impl From<VerificationError<jose::Error>> for Error {
    fn from(e: VerificationError<jose::Error>) -> Self {
        Self::Ucan(e.into())
    }
}

impl<U: std::error::Error> From<WebauthnError> for Error<U, WebauthnError> {
    fn from(e: WebauthnError) -> Self {
        Self::Webauthn(e)
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<'r, U, NB, W, R> CacaoVerifier<CommonCacao<U, NB, W>> for CommonVerifier<R>
where
    R: 'r + Send + Sync + CacaoVerifier<UcanCacao<U, NB>> + CacaoVerifier<WebauthnCacao<W, NB>>,
    U: Send + Sync + for<'a> Deserialize<'a> + Serialize + Clone,
    NB: Send + Sync + for<'a> Deserialize<'a> + Serialize + Clone,
    W: Send + Sync + for<'a> Deserialize<'a> + Serialize + Clone,
{
    type Error = Error<
        <R as CacaoVerifier<UcanCacao<U, NB>>>::Error,
        <R as CacaoVerifier<WebauthnCacao<W, NB>>>::Error,
    >;

    async fn verify(&self, cacao: &CommonCacao<U, NB, W>) -> Result<(), Self::Error> {
        match RecapCacao::try_from(cacao.clone()) {
            Ok(recap) => self.verify(&recap).await?,
            Err(c) => match UcanCacao::try_from(c) {
                Ok(ucan) => self.verify(&ucan).await.map_err(Error::Ucan)?,
                Err(c) => match WebauthnCacao::try_from(c) {
                    Ok(webauthn) => self.verify(&webauthn).await.map_err(Error::Webauthn)?,
                    Err(_) => {
                        return Err(Error::Mismatch);
                    }
                },
            },
        };
        Ok(())
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<NB, R> CacaoVerifier<RecapCacao<NB>> for CommonVerifier<R>
where
    R: Send + Sync,
    NB: Send + Sync + for<'a> Deserialize<'a> + Serialize + Clone,
{
    type Error = RecapError;

    async fn verify(&self, cacao: &RecapCacao<NB>) -> Result<(), Self::Error> {
        RecapVerify::default().verify(cacao).await
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<'r, NB, R, F> CacaoVerifier<UcanCacao<F, NB>> for CommonVerifier<R>
where
    R: 'r + Send + Sync + CacaoVerifier<UcanCacao<F, NB>>,
    F: Send + Sync + for<'a> Deserialize<'a> + Serialize + Clone,
    NB: Send + Sync + for<'a> Deserialize<'a> + Serialize + Clone,
{
    type Error = R::Error;

    async fn verify(&self, cacao: &UcanCacao<F, NB>) -> Result<(), Self::Error> {
        self.0.verify(cacao).await
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<'r, NB, R, F> CacaoVerifier<WebauthnCacao<F, NB>> for CommonVerifier<R>
where
    R: 'r + Send + Sync + CacaoVerifier<WebauthnCacao<F, NB>>,
    F: Send + Sync + for<'a> Deserialize<'a> + Serialize + Clone,
    NB: Send + Sync + for<'a> Deserialize<'a> + Serialize + Clone,
{
    type Error = R::Error;

    async fn verify(&self, cacao: &WebauthnCacao<F, NB>) -> Result<(), Self::Error> {
        self.0.verify(cacao).await
    }
}

macro_rules! impl_from {
    ($from:ty, $typ:tt) => {
        impl<U, NB, W> From<$from> for CommonCacao<U, NB, W> {
            fn from(from: $from) -> Self {
                CommonCacao {
                    issuer: from.issuer,
                    audience: from.audience,
                    attenuations: from.attenuations,
                    nonce: from.nonce,
                    proof: from.proof,
                    issued_at: from.issued_at,
                    not_before: from.not_before,
                    expiration: from.expiration,
                    typ: Types::$typ(Type {
                        facts: from.facts,
                        signature: from.signature,
                        version: from.version,
                    }),
                }
            }
        }
    };
}

impl_from!(RecapCacao<NB>, Recap);
impl_from!(UcanCacao<U, NB>, Ucan);
impl_from!(WebauthnCacao<W, NB>, Webauthn);

macro_rules! impl_tryfrom {
    ($into:ty, $typ:tt) => {
        impl<U, NB, W> TryFrom<CommonCacao<U, NB, W>> for $into {
            type Error = CommonCacao<U, NB, W>;
            fn try_from(cacao: CommonCacao<U, NB, W>) -> Result<Self, Self::Error> {
                match cacao.typ {
                    Types::$typ(Type {
                        version,
                        facts,
                        signature,
                    }) => Ok(Self {
                        issuer: cacao.issuer,
                        audience: cacao.audience,
                        version,
                        attenuations: cacao.attenuations,
                        nonce: cacao.nonce,
                        proof: cacao.proof,
                        issued_at: cacao.issued_at,
                        not_before: cacao.not_before,
                        expiration: cacao.expiration,
                        facts,
                        signature,
                    }),
                    _ => Err(cacao),
                }
            }
        }
    };
}

impl_tryfrom!(RecapCacao<NB>, Recap);
impl_tryfrom!(UcanCacao<U, NB>, Ucan);
impl_tryfrom!(WebauthnCacao<W, NB>, Webauthn);

impl<U, NB, W> TryFrom<Ucan<U, NB, jose::Signature>> for CommonCacao<BTreeMap<String, U>, NB, W> {
    type Error = UcanError;
    fn try_from(ucan: Ucan<U, NB, jose::Signature>) -> Result<Self, Self::Error> {
        Ok(UcanCacao::try_from(ucan)?.into())
    }
}

impl<F, NB> TryFrom<(Message, [u8; 65])> for CommonCacao<F, NB>
where
    NB: for<'d> Deserialize<'d>,
{
    type Error = RecapError;
    fn try_from(siwe: (Message, [u8; 65])) -> Result<Self, Self::Error> {
        Ok(RecapCacao::try_from(siwe)?.into())
    }
}

impl<U, NB, W> CommonCacao<U, NB, W> {
    fn ser_len(&self) -> usize {
        5 + self.nonce().map_or(0usize, |_| 1)
            + self.proof().map_or(0usize, |_| 1)
            + self.issued_at().map_or(0usize, |_| 1)
            + self.not_before().map_or(0usize, |_| 1)
            + self.expiration().map_or(0usize, |_| 1)
            + self.facts().map_or(0usize, |_| 1)
    }
}

// because we can't use the `#[serde(flatten)]` attribute when serializing dagcbor
impl<U: Serialize, NB: Serialize, W: Serialize> Serialize for CommonCacao<U, NB, W> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut map = serializer.serialize_struct("CommonCacao", self.ser_len())?;
        map.serialize_field("att", &self.attenuations)?;
        map.serialize_field("aud", &self.audience)?;
        if let Some(expiration) = self.expiration() {
            map.serialize_field("exp", &expiration)?;
        };
        if let Some(facts) = self.facts() {
            map.serialize_field("fct", &facts)?;
        };
        if let Some(issued_at) = self.issued_at() {
            map.serialize_field("iat", &issued_at)?;
        };
        map.serialize_field("iss", &self.issuer)?;
        if let Some(not_before) = self.not_before() {
            map.serialize_field("nbf", &not_before)?;
        };
        if let Some(nonce) = self.nonce() {
            map.serialize_field("nnc", &nonce)?;
        };
        if let Some(proof) = self.proof() {
            map.serialize_field("prf", &proof)?;
        };
        match &self.typ {
            Types::Ucan(t) => {
                map.serialize_field("s", &t.signature)?;
                map.serialize_field("v", &t.version)?;
            }
            Types::Recap(t) => {
                map.serialize_field("s", &t.signature)?;
                map.serialize_field("v", &t.version)?;
            }
            Types::Webauthn(t) => {
                map.serialize_field("s", &t.signature)?;
                map.serialize_field("v", &t.version)?;
            }
        };
        map.end()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[async_std::test]
    async fn basic() {
        let encoded = [
            "qmNpc3NYG50aygECAbFNPE9fv7z7mK8tMwAA1JyVuTqnAGNhdWRYVp0a7QE4NstKM22BZAAHaojdiik61NN1l7wVRKwcQJWixAbFHzEjejZNa2lFaExWMmVxOWFqelBRQTZRMkJVU2t6WHdUMm1GYkR2TkdqTXl0VzRTV2g0YXZhMWNhdHSheEtrZXBsZXI6cGtoOmVpcDE1NToxOjB4QjE0ZDNjNEY1RkJGQkNGQjk4YWYyZDMzMDAwMGQ0OWM5NUI5M2FBNzovL2RlZmF1bHQva3alZmt2L2RlbIGgZmt2L2dldIGgZmt2L3B1dIGgZ2t2L2xpc3SBoGtrdi9tZXRhZGF0YYGgY25uY3FVajg5YkdHWmtoNFJKNjY4dmNwcmaAY2lhdBocvbpSY2V4cBsAAAAHda9C0mNmY3SkZWlhdC16ZC41MlplZXhwLXpkLjUyWmZkb21haW5pbG9jYWxob3N0aXJlc291cmNlc4Bhc1hINOcBG5HDAwx4ASjJGspMdIhMu2NX9o06hfQbz1SqCvdAWjwWOpO6aDh56KfReehDpmKEJxYXdQVVLMAmFVq1SZxBIzljSnkc",
            "pWNhdHSheEZrZXBsZXI6a2V5OnpEbmFlV1JVd3JvY05MOTdnOEw0ZTZTY3VDYmNrcFFoQzIxRktMR25CSkxRR2NzMmc6Ly9kZWZhdWx0oWpvcmJpdC9ob3N0gaBjYXVkWCWdGu0Bb0rW8YlySQ1v4l7PKVDoDmcsosRAzcijJGmepZrIc4oAY2lzc1gmnRqAJAJZBlltN8cQWrIUuEk4ixMQja39vremwH3pkS1Pw0iTcQBhc1j4NPLMAYgBeyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiRWlBekNYSmRNTDJ1LVNBWUZTVi1CR2g2Y0FxeVkzU0pUallyQVdueVpmNTNfQSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODAwMCIsImNyb3NzT3JpZ2luIjp0cnVlfSVJlg3liA6MaHQ0Fw9kdmBbj-SuuaKGMseZXPO6gx2XYwUAAAAAgCQSce0x-XfSHCx2JcTX5p95E0yKSjp-WXf93nZ5whHTrlTAgII6yBZtWnNnd6o_GAkBMJmDcrNtLPoMV2THvb0KXBNhdmR3YW4z"
        ];
        let verifier = CommonVerifier::new(&did_method_key::DIDKey);
        for e in encoded {
            let decoded = base64::decode_config(e, base64::URL_SAFE_NO_PAD).unwrap();
            let cacao: CommonCacao = serde_ipld_dagcbor::from_slice(&decoded).unwrap();
            cacao.verify(&verifier).await.unwrap();
        }
    }
}
