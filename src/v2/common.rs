use super::{
    recap_cacao::{Error as RecapError, RecapCacao, RecapFacts, RecapSignature, RecapVerify},
    ucan_cacao::{Error as UcanError, UcanCacao, UcanFacts, UcanSignature},
    Cacao, CacaoVerifier,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use ssi_ucan::{common::Common, jose::Signature, jwt::UcanEncode, Payload, Ucan};
use varsig::{common::JoseSig, either::EitherSignature, VarSig};

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

impl<F, NB> CommonCacao<F, NB> {
    pub fn get_ucan(self) -> Option<Ucan<Common, F, NB>> {
        let signature = match self.signature.into_inner() {
            EitherSignature::A(_) => return None,
            EitherSignature::B(ucan) => match ucan {
                EitherSignature::A(JoseSig::EdDSA(s)) => {
                    Common::Jose(Signature::EdDSA(s.into_inner()))
                }
                EitherSignature::A(JoseSig::Es256(s)) => {
                    Common::Jose(Signature::ES256(s.into_inner()))
                }
                EitherSignature::A(JoseSig::Es512(s)) => {
                    Common::Jose(Signature::ES512(s.into_inner()))
                }
                EitherSignature::A(JoseSig::Es256K(s)) => {
                    Common::Jose(Signature::ES256K(s.into_inner()))
                }
                EitherSignature::A(JoseSig::Rsa256(s)) => {
                    Common::Jose(Signature::RS256(s.into_inner()))
                }
                EitherSignature::A(JoseSig::Rsa512(s)) => {
                    Common::Jose(Signature::RS512(s.into_inner()))
                }
                EitherSignature::B(webauthn) => Common::Webauthn(webauthn.into_inner()),
            },
        };
        let mut payload = Payload::new(self.issuer.to_string(), self.audience.to_string());
        payload.capabilities = self.attenuations;
        payload.nonce = self.nonce;
        payload.proof = self.proof;
        payload.issued_at = self.issued_at;
        payload.not_before = self.not_before;
        payload.expiration = self.expiration;
        payload.facts = self.facts.and_then(|f| match f {
            CommonFacts::Ucan(f) => Some(f),
            CommonFacts::Recap(_) => None,
        });
        Some(payload.sign(signature))
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
            CommonSignature::B(_) => self
                .clone()
                .get_ucan()
                .map(|ucan| ucan.encode())
                .transpose()?,
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

impl From<ssi_ucan::Error> for Error {
    fn from(e: ssi_ucan::Error) -> Self {
        Self::Ucan(e.into())
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<'r, NB, R, F> CacaoVerifier<CommonSignature, CommonFacts<F>, NB> for CommonVerifier<R>
where
    R: 'r + Send + Sync + CacaoVerifier<UcanSignature, UcanFacts<F>, NB>,
    F: Send + Sync + for<'a> Deserialize<'a> + Serialize + Clone,
    NB: Send + Sync + for<'a> Deserialize<'a> + Serialize + Clone,
{
    type Error = Error<R::Error>;

    async fn verify(&self, cacao: &CommonCacao<F, NB>) -> Result<(), Self::Error> {
        Ok(match RecapCacao::try_from(cacao.clone()) {
            Ok(recap) => self.verify(&recap).await?,
            Err(c) => match UcanCacao::try_from(c) {
                Ok(ucan) => self.verify(&ucan).await.map_err(Error::Ucan)?,
                Err(_) => {
                    return Err(Error::Mismatch);
                }
            },
        })
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<NB, R> CacaoVerifier<RecapSignature, RecapFacts, NB> for CommonVerifier<R>
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
impl<'r, NB, R, F> CacaoVerifier<UcanSignature, UcanFacts<F>, NB> for CommonVerifier<R>
where
    R: 'r + Send + Sync + CacaoVerifier<UcanSignature, UcanFacts<F>, NB>,
    F: Send + Sync + for<'a> Deserialize<'a> + Serialize + Clone,
    NB: Send + Sync + for<'a> Deserialize<'a> + Serialize + Clone,
{
    type Error = R::Error;

    async fn verify(&self, cacao: &UcanCacao<F, NB>) -> Result<(), Self::Error> {
        (&self.0).verify(cacao).await
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

impl<F, NB> TryFrom<Ucan<Common, F, NB>> for CommonCacao<F, NB> {
    type Error = Error;
    fn try_from(ucan: Ucan<Common, F, NB>) -> Result<Self, Self::Error> {
        Ok(UcanCacao::try_from(ucan)
            .map(Self::from)
            .map_err(Error::Ucan)?)
    }
}
