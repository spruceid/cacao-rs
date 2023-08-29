use super::{
    recap_cacao::{Error as RecapError, RecapCacao, RecapFacts, RecapSignature, RecapVerify},
    ucan_cacao::{Error as UcanError, UcanCacao, UcanFacts, UcanSignature},
    Cacao, CacaoVerifier,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use ssi_dids::did_resolve::DIDResolver;
use varsig::{either::EitherSignature, VarSig};

type CommonSignature = EitherSignature<RecapSignature, UcanSignature>;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Eq, PartialOrd, Hash)]
#[serde(untagged)]
pub enum CommonFacts<F = Value> {
    Recap(RecapFacts),
    Ucan(UcanFacts<F>),
}

pub type CommonCacao<F = Value, NB = Value> = Cacao<CommonSignature, CommonFacts<F>, NB>;

pub struct CommonVerifier<T>(T);

impl<T> CommonVerifier<T> {
    pub fn new(t: T) -> Self {
        Self(t)
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Ucan(#[from] UcanError),
    #[error(transparent)]
    Recap(#[from] RecapError),
    #[error("Signature and Facts Mismatch")]
    Mismatch,
}

#[async_trait]
impl<NB, R, F> CacaoVerifier<CommonSignature, CommonFacts<F>, NB> for CommonVerifier<R>
where
    R: Send + Sync + DIDResolver,
    F: Send + Sync + for<'a> Deserialize<'a> + Serialize + Clone,
    NB: Send + Sync + for<'a> Deserialize<'a> + Serialize + Clone,
{
    type Error = Error;

    async fn verify(&self, cacao: &CommonCacao<F, NB>) -> Result<(), Self::Error> {
        Ok(match RecapCacao::try_from(cacao.clone()) {
            Ok(recap) => self.verify(&recap).await?,
            Err(c) => match UcanCacao::try_from(c) {
                Ok(ucan) => self.verify(&ucan).await?,
                Err(_) => {
                    return Err(Error::Mismatch);
                }
            },
        })
    }
}

#[async_trait]
impl<NB, R> CacaoVerifier<RecapSignature, RecapFacts, NB> for CommonVerifier<R>
where
    R: Send + Sync + DIDResolver,
    NB: Send + Sync + for<'a> Deserialize<'a> + Serialize + Clone,
{
    type Error = RecapError;

    async fn verify(&self, cacao: &RecapCacao<NB>) -> Result<(), Self::Error> {
        RecapVerify::default().verify(cacao).await
    }
}

#[async_trait]
impl<NB, R, F> CacaoVerifier<UcanSignature, UcanFacts<F>, NB> for CommonVerifier<R>
where
    R: Send + Sync + DIDResolver,
    F: Send + Sync + for<'a> Deserialize<'a> + Serialize + Clone,
    NB: Send + Sync + for<'a> Deserialize<'a> + Serialize + Clone,
{
    type Error = UcanError;

    async fn verify(&self, cacao: &UcanCacao<F, NB>) -> Result<(), Self::Error> {
        self.0.verify(cacao).await
    }
}

impl<F, NB> From<RecapCacao<NB>> for CommonCacao<F, NB> {
    fn from(recap: RecapCacao<NB>) -> Self {
        CommonCacao {
            issuer: recap.issuer,
            audience: recap.audience,
            version: recap.version,
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
            version: ucan.version,
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
        match (cacao.facts, cacao.signature.into_inner()) {
            (Some(CommonFacts::Recap(facts)), EitherSignature::A(sig)) => Ok(RecapCacao {
                issuer: cacao.issuer,
                audience: cacao.audience,
                version: cacao.version,
                attenuations: cacao.attenuations,
                nonce: cacao.nonce,
                proof: cacao.proof,
                issued_at: cacao.issued_at,
                not_before: cacao.not_before,
                expiration: cacao.expiration,
                facts: Some(facts),
                signature: VarSig::new(sig),
            }),
            (facts, sig) => Err(CommonCacao {
                issuer: cacao.issuer,
                audience: cacao.audience,
                version: cacao.version,
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
        match (cacao.facts, cacao.signature.into_inner()) {
            (Some(CommonFacts::Ucan(facts)), EitherSignature::B(sig)) => Ok(UcanCacao {
                issuer: cacao.issuer,
                audience: cacao.audience,
                version: cacao.version,
                attenuations: cacao.attenuations,
                nonce: cacao.nonce,
                proof: cacao.proof,
                issued_at: cacao.issued_at,
                not_before: cacao.not_before,
                expiration: cacao.expiration,
                facts: Some(facts),
                signature: VarSig::new(sig),
            }),
            (None, EitherSignature::B(sig)) => Ok(UcanCacao {
                issuer: cacao.issuer,
                audience: cacao.audience,
                version: cacao.version,
                attenuations: cacao.attenuations,
                nonce: cacao.nonce,
                proof: cacao.proof,
                issued_at: cacao.issued_at,
                not_before: cacao.not_before,
                expiration: cacao.expiration,
                facts: None,
                signature: VarSig::new(sig),
            }),
            (facts, sig) => Err(CommonCacao {
                issuer: cacao.issuer,
                audience: cacao.audience,
                version: cacao.version,
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
