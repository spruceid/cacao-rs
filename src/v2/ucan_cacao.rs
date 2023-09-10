use super::{Cacao, CacaoVerifier};
use async_trait::async_trait;
use multidid::MultiDid;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use ssi_dids::did_resolve::DIDResolver;
use ssi_ucan::{
    common::Common, jose::Signature, jwt::Algorithm, webauthn::Webauthn, Payload, Ucan,
};
use std::collections::BTreeMap;
use std::str::FromStr;
use varsig::{
    common::{
        Ed25519, Es256, Es256K, Es512, JoseSig, PasskeySig, Rsa256, Rsa512, DAG_CBOR_ENCODING,
    },
    EitherSignature, VarSig,
};

pub type UcanSignature = EitherSignature<JoseSig<DAG_CBOR_ENCODING>, PasskeySig<DAG_CBOR_ENCODING>>;
pub type UcanFacts<F> = BTreeMap<String, F>;
pub type UcanCacao<F = Value, NB = Value> = Cacao<UcanSignature, UcanFacts<F>, NB>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Unsupported Algorithm")]
    UnsupportedAlgorithm(Algorithm),
    #[error("Incorrect Signature Length: recieved {0}, expected {1}")]
    IncorrectSignatureLength(usize, usize),
    #[error(transparent)]
    MultididParse(#[from] multidid::ParseErr),
    #[error(transparent)]
    Ucan(#[from] ssi_ucan::Error),
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<NB, R, F> CacaoVerifier<UcanSignature, UcanFacts<F>, NB> for &R
where
    R: DIDResolver,
    F: Send + Sync + for<'a> Deserialize<'a> + Serialize + Clone,
    NB: Send + Sync + for<'a> Deserialize<'a> + Serialize + Clone,
{
    type Error = Error;

    async fn verify(&self, cacao: &UcanCacao<F, NB>) -> Result<(), Self::Error> {
        let ucan = Ucan::<Common, F, NB>::from(cacao.clone()).encode_jwt()?;
        Ucan::<Signature, F, NB>::decode_and_verify(&ucan, *self).await?;
        Ok(())
    }
}

impl<F, NB> TryFrom<Ucan<Signature, F, NB>> for UcanCacao<F, NB> {
    type Error = Error;
    fn try_from(ucan: Ucan<Signature, F, NB>) -> Result<Self, Self::Error> {
        let (payload, signature) = ucan.into_inner();
        Ok(Self {
            issuer: MultiDid::from_str(&payload.issuer)?,
            audience: MultiDid::from_str(&payload.audience)?,
            version: "0.2.0".to_string(),
            attenuations: payload.capabilities,
            nonce: payload.nonce,
            proof: payload.proof,
            issued_at: payload.issued_at,
            not_before: payload.not_before,
            expiration: payload.expiration,
            facts: payload.facts,
            signature: VarSig::new(match signature {
                Signature::ES256(sig) => EitherSignature::A(JoseSig::Es256(Es256::new(sig))),
                Signature::ES512(sig) => EitherSignature::A(JoseSig::Es512(Es512::new(sig))),
                Signature::EdDSA(sig) => EitherSignature::A(JoseSig::EdDSA(Ed25519::new(sig))),
                Signature::RS256(sig) => EitherSignature::A(JoseSig::Rsa256(Rsa256::new(sig))),
                Signature::RS512(sig) => EitherSignature::A(JoseSig::Rsa512(Rsa512::new(sig))),
                Signature::ES256K(sig) => EitherSignature::A(JoseSig::Es256K(Es256K::new(sig))),
            }),
        })
    }
}

impl<F, NB> TryFrom<Ucan<Common, F, NB>> for UcanCacao<F, NB> {
    type Error = Error;
    fn try_from(ucan: Ucan<Common, F, NB>) -> Result<Self, Self::Error> {
        let (payload, signature) = ucan.into_inner();
        Ok(Self {
            issuer: MultiDid::from_str(&payload.issuer)?,
            audience: MultiDid::from_str(&payload.audience)?,
            version: "0.2.0".to_string(),
            attenuations: payload.capabilities,
            nonce: payload.nonce,
            proof: payload.proof,
            issued_at: payload.issued_at,
            not_before: payload.not_before,
            expiration: payload.expiration,
            facts: payload.facts,
            signature: VarSig::new(match signature {
                Common::Jose(Signature::ES256(sig)) => {
                    EitherSignature::A(JoseSig::Es256(Es256::new(sig)))
                }
                Common::Jose(Signature::ES512(sig)) => {
                    EitherSignature::A(JoseSig::Es512(Es512::new(sig)))
                }
                Common::Jose(Signature::EdDSA(sig)) => {
                    EitherSignature::A(JoseSig::EdDSA(Ed25519::new(sig)))
                }
                Common::Jose(Signature::RS256(sig)) => {
                    EitherSignature::A(JoseSig::Rsa256(Rsa256::new(sig)))
                }
                Common::Jose(Signature::RS512(sig)) => {
                    EitherSignature::A(JoseSig::Rsa512(Rsa512::new(sig)))
                }
                Common::Jose(Signature::ES256K(sig)) => {
                    EitherSignature::A(JoseSig::Es256K(Es256K::new(sig)))
                }
                Common::Webauthn(sig) => EitherSignature::B(PasskeySig::new(sig)),
                Common::Generic(_) => return Err(Error::UnsupportedAlgorithm(Algorithm::None)),
            }),
        })
    }
}

impl<F, NB> TryFrom<Ucan<Webauthn, F, NB>> for UcanCacao<F, NB> {
    type Error = Error;
    fn try_from(ucan: Ucan<Webauthn, F, NB>) -> Result<Self, Self::Error> {
        let (payload, signature) = ucan.into_inner();
        Ok(Self {
            issuer: MultiDid::from_str(&payload.issuer)?,
            audience: MultiDid::from_str(&payload.audience)?,
            version: "0.2.0".to_string(),
            attenuations: payload.capabilities,
            nonce: payload.nonce,
            proof: payload.proof,
            issued_at: payload.issued_at,
            not_before: payload.not_before,
            expiration: payload.expiration,
            facts: payload.facts,
            signature: VarSig::new(EitherSignature::B(PasskeySig::new(signature))),
        })
    }
}

impl<F, NB> From<UcanCacao<F, NB>> for Ucan<Common, F, NB> {
    fn from(cacao: UcanCacao<F, NB>) -> Self {
        let signature = match cacao.signature.into_inner() {
            EitherSignature::A(JoseSig::EdDSA(s)) => Common::Jose(Signature::EdDSA(s.into_inner())),
            EitherSignature::A(JoseSig::Es256(s)) => Common::Jose(Signature::ES256(s.into_inner())),
            EitherSignature::A(JoseSig::Es512(s)) => Common::Jose(Signature::ES512(s.into_inner())),
            EitherSignature::A(JoseSig::Es256K(s)) => {
                Common::Jose(Signature::ES256K(s.into_inner()))
            }
            EitherSignature::A(JoseSig::Rsa256(s)) => {
                Common::Jose(Signature::RS256(s.into_inner()))
            }
            EitherSignature::A(JoseSig::Rsa512(s)) => {
                Common::Jose(Signature::RS512(s.into_inner()))
            }
            EitherSignature::B(passkey) => Common::Webauthn(passkey.into_inner()),
        };
        let mut payload = Payload::new(cacao.issuer.to_string(), cacao.audience.to_string());
        payload.capabilities = cacao.attenuations;
        payload.nonce = cacao.nonce;
        payload.proof = cacao.proof;
        payload.issued_at = cacao.issued_at;
        payload.not_before = cacao.not_before;
        payload.expiration = cacao.expiration;
        payload.facts = cacao.facts;
        payload.sign(signature)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn tz() {
        use time::OffsetDateTime;
        let time = OffsetDateTime::now_local().unwrap();
        println!("{}", time.offset());
    }
}
