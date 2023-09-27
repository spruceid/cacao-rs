use super::{
    recap_cacao::{
        version::SiweVersion, Error as RecapError, RecapCacao, RecapFacts, RecapSignature,
        RecapVerify,
    },
    ucan_cacao::{Error as UcanError, UcanCacao, UcanFacts, UcanSignature},
    Cacao, CacaoVerifier,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use siwe::Message;
use ssi_ucan::{
    jose::{self, Signature, VerificationError},
    version::SemanticVersion,
    Ucan,
};
use varsig::{either::EitherSignature, VarSig};

type CommonSignature = EitherSignature<RecapSignature, UcanSignature>;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Eq, PartialOrd, Hash)]
#[serde(untagged)]
pub enum CommonFacts<F = Value> {
    Recap(RecapFacts),
    Ucan(UcanFacts<F>),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Eq, PartialOrd, Hash)]
#[serde(untagged)]
pub enum CommonVersions {
    Recap(SiweVersion),
    Ucan(SemanticVersion),
}

pub type CommonCacao<F = Value, NB = Value> =
    Cacao<CommonVersions, CommonSignature, CommonFacts<F>, NB>;

#[derive(Debug, Clone, PartialEq, Default)]
pub struct CommonVerifier<T>(T);

impl<T> CommonVerifier<T> {
    pub fn new(t: T) -> Self {
        Self(t)
    }
}

impl<F, NB> CommonCacao<F, NB>
where
    F: Clone + Serialize,
    NB: Clone + Serialize,
{
    pub fn serialize_jwt(&self) -> Result<Option<String>, Error> {
        Ok(match self.signature.sig() {
            CommonSignature::A(_) => None,
            CommonSignature::B(_) => UcanCacao::<F, NB>::try_from(self.clone())
                .ok()
                .map(|uc| Ucan::<F, NB>::from(uc).encode())
                .transpose()
                .map_err(|e| Error::Ucan(e.into()))?,
        })
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error<U: std::error::Error = UcanError> {
    #[error(transparent)]
    Ucan(U),
    #[error(transparent)]
    Recap(#[from] RecapError),
    #[error("Signature and Facts Mismatch")]
    Mismatch,
}

impl From<UcanError> for Error {
    fn from(e: UcanError) -> Self {
        Self::Ucan(e)
    }
}

impl From<VerificationError<jose::Error>> for Error {
    fn from(e: VerificationError<jose::Error>) -> Self {
        Self::Ucan(e.into())
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<'r, NB, R, F> CacaoVerifier<CommonVersions, CommonSignature, CommonFacts<F>, NB>
    for CommonVerifier<R>
where
    R: 'r + Send + Sync + CacaoVerifier<SemanticVersion, UcanSignature, UcanFacts<F>, NB>,
    F: Send + Sync + for<'a> Deserialize<'a> + Serialize + Clone,
    NB: Send + Sync + for<'a> Deserialize<'a> + Serialize + Clone,
{
    type Error = Error<R::Error>;

    async fn verify(&self, cacao: &CommonCacao<F, NB>) -> Result<(), Self::Error> {
        match RecapCacao::try_from(cacao.clone()) {
            Ok(recap) => self.verify(&recap).await?,
            Err(c) => match UcanCacao::try_from(c) {
                Ok(ucan) => self.verify(&ucan).await.map_err(Error::Ucan)?,
                Err(_) => {
                    return Err(Error::Mismatch);
                }
            },
        };
        Ok(())
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<NB, R> CacaoVerifier<SiweVersion, RecapSignature, RecapFacts, NB> for CommonVerifier<R>
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
impl<'r, NB, R, F> CacaoVerifier<SemanticVersion, UcanSignature, UcanFacts<F>, NB>
    for CommonVerifier<R>
where
    R: 'r + Send + Sync + CacaoVerifier<SemanticVersion, UcanSignature, UcanFacts<F>, NB>,
    F: Send + Sync + for<'a> Deserialize<'a> + Serialize + Clone,
    NB: Send + Sync + for<'a> Deserialize<'a> + Serialize + Clone,
{
    type Error = R::Error;

    async fn verify(&self, cacao: &UcanCacao<F, NB>) -> Result<(), Self::Error> {
        self.0.verify(cacao).await
    }
}

impl<F, NB> From<RecapCacao<NB>> for CommonCacao<F, NB> {
    fn from(recap: RecapCacao<NB>) -> Self {
        CommonCacao {
            issuer: recap.issuer,
            audience: recap.audience,
            version: CommonVersions::Recap(recap.version),
            attenuations: recap.attenuations,
            nonce: recap.nonce,
            proof: recap.proof,
            issued_at: recap.issued_at,
            not_before: recap.not_before,
            expiration: recap.expiration,
            facts: recap.facts.map(CommonFacts::Recap),
            signature: VarSig::new(EitherSignature::A(recap.signature.into_inner())),
        }
    }
}

impl<F, NB> From<UcanCacao<F, NB>> for CommonCacao<F, NB> {
    fn from(ucan: UcanCacao<F, NB>) -> Self {
        CommonCacao {
            issuer: ucan.issuer,
            audience: ucan.audience,
            version: CommonVersions::Ucan(ucan.version),
            attenuations: ucan.attenuations,
            nonce: ucan.nonce,
            proof: ucan.proof,
            issued_at: ucan.issued_at,
            not_before: ucan.not_before,
            expiration: ucan.expiration,
            facts: ucan.facts.map(CommonFacts::Ucan),
            signature: VarSig::new(EitherSignature::B(ucan.signature.into_inner())),
        }
    }
}

impl<F, NB> TryFrom<CommonCacao<F, NB>> for RecapCacao<NB> {
    type Error = CommonCacao<F, NB>;
    fn try_from(cacao: CommonCacao<F, NB>) -> Result<Self, Self::Error> {
        match (cacao.facts, cacao.signature.into_inner(), cacao.version) {
            (
                Some(CommonFacts::Recap(facts)),
                EitherSignature::A(sig),
                CommonVersions::Recap(version),
            ) => Ok(RecapCacao {
                issuer: cacao.issuer,
                audience: cacao.audience,
                version,
                attenuations: cacao.attenuations,
                nonce: cacao.nonce,
                proof: cacao.proof,
                issued_at: cacao.issued_at,
                not_before: cacao.not_before,
                expiration: cacao.expiration,
                facts: Some(facts),
                signature: VarSig::new(sig),
            }),
            (facts, sig, version) => Err(CommonCacao {
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
                signature: VarSig::new(sig),
            }),
        }
    }
}

impl<F, NB> TryFrom<CommonCacao<F, NB>> for UcanCacao<F, NB> {
    type Error = CommonCacao<F, NB>;
    fn try_from(cacao: CommonCacao<F, NB>) -> Result<Self, Self::Error> {
        match (cacao.facts, cacao.signature.into_inner(), cacao.version) {
            (
                Some(CommonFacts::Ucan(facts)),
                EitherSignature::B(sig),
                CommonVersions::Ucan(version),
            ) => Ok(UcanCacao {
                issuer: cacao.issuer,
                audience: cacao.audience,
                version,
                attenuations: cacao.attenuations,
                nonce: cacao.nonce,
                proof: cacao.proof,
                issued_at: cacao.issued_at,
                not_before: cacao.not_before,
                expiration: cacao.expiration,
                facts: Some(facts),
                signature: VarSig::new(sig),
            }),
            (None, EitherSignature::B(sig), CommonVersions::Ucan(version)) => Ok(UcanCacao {
                issuer: cacao.issuer,
                audience: cacao.audience,
                version,
                attenuations: cacao.attenuations,
                nonce: cacao.nonce,
                proof: cacao.proof,
                issued_at: cacao.issued_at,
                not_before: cacao.not_before,
                expiration: cacao.expiration,
                facts: None,
                signature: VarSig::new(sig),
            }),
            (facts, sig, version) => Err(CommonCacao {
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
                signature: VarSig::new(sig),
            }),
        }
    }
}

impl<F, NB> TryFrom<Ucan<F, NB, Signature>> for CommonCacao<F, NB> {
    type Error = Error;
    fn try_from(ucan: Ucan<F, NB, Signature>) -> Result<Self, Self::Error> {
        Ok(UcanCacao::try_from(ucan)?.into())
    }
}

impl<F, NB> TryFrom<(Message, [u8; 65])> for CommonCacao<F, NB>
where
    NB: for<'d> Deserialize<'d>,
{
    type Error = Error;
    fn try_from(siwe: (Message, [u8; 65])) -> Result<Self, Self::Error> {
        Ok(RecapCacao::try_from(siwe)?.into())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[async_std::test]
    async fn basic() {
        let encoded = "qmNpc3NYG50aygECAbFNPE9fv7z7mK8tMwAA1JyVuTqnAGNhdWRYVp0a7QE4NstKM22BZAAHaojdiik61NN1l7wVRKwcQJWixAbFHzEjejZNa2lFaExWMmVxOWFqelBRQTZRMkJVU2t6WHdUMm1GYkR2TkdqTXl0VzRTV2g0YXZhMWNhdHSheEtrZXBsZXI6cGtoOmVpcDE1NToxOjB4QjE0ZDNjNEY1RkJGQkNGQjk4YWYyZDMzMDAwMGQ0OWM5NUI5M2FBNzovL2RlZmF1bHQva3alZmt2L2RlbIGgZmt2L2dldIGgZmt2L3B1dIGgZ2t2L2xpc3SBoGtrdi9tZXRhZGF0YYGgY25uY3FVajg5YkdHWmtoNFJKNjY4dmNwcmaAY2lhdBocvbpSY2V4cBsAAAAHda9C0mNmY3SkZWlhdC16ZC41MlplZXhwLXpkLjUyWmZkb21haW5pbG9jYWxob3N0aXJlc291cmNlc4Bhc1hINOcBG5HDAwx4ASjJGspMdIhMu2NX9o06hfQbz1SqCvdAWjwWOpO6aDh56KfReehDpmKEJxYXdQVVLMAmFVq1SZxBIzljSnkc";
        let decoded = base64::decode(encoded).unwrap();
        let cacao: CommonCacao = serde_ipld_dagcbor::from_slice(&decoded).unwrap();
        let verifier = CommonVerifier::new(&did_method_key::DIDKey);
        cacao.verify(&verifier).await.unwrap();
    }
}
