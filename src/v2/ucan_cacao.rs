use super::{Cacao, CacaoVerifier};
use async_trait::async_trait;
use multidid::MultiDid;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use ssi_dids::did_resolve::DIDResolver;
use ssi_jwk::Algorithm;
use ssi_ucan::{Payload, Ucan};
use std::collections::BTreeMap;
use std::str::FromStr;
use varsig::{
    common::{Ed25519, Es256, Es256K, JoseSig, Rsa256, Rsa512, DAG_JSON_ENCODING},
    VarSig,
};

pub type UcanSignature = JoseSig<DAG_JSON_ENCODING>;
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

impl<F, NB> TryFrom<Ucan<F, NB>> for UcanCacao<F, NB> {
    type Error = Error;
    fn try_from(ucan: Ucan<F, NB>) -> Result<Self, Self::Error> {
        let (alg, payload, signature) = ucan.into_inner();
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
            signature: VarSig::new(match_alg(alg, signature)?),
        })
    }
}

impl<F, NB> From<UcanCacao<F, NB>> for Ucan<F, NB> {
    fn from(cacao: UcanCacao<F, NB>) -> Self {
        let (algorithm, signature) = match cacao.signature.into_inner() {
            JoseSig::Ed25519(s) => (Algorithm::EdDSA, s.bytes().to_vec()),
            JoseSig::Es256(s) => (Algorithm::ES256, s.bytes().to_vec()),
            JoseSig::Es512(s) => (Algorithm::ES256, s.bytes().to_vec()),
            JoseSig::Es256K(s) => (Algorithm::ES256K, s.bytes().to_vec()),
            JoseSig::Rsa256(s) => (Algorithm::RS256, s.bytes().to_vec()),
            JoseSig::Rsa512(s) => (Algorithm::RS512, s.bytes().to_vec()),
        };
        let mut payload = Payload::new(cacao.issuer.to_string(), cacao.audience.to_string());
        payload.capabilities = cacao.attenuations;
        payload.nonce = cacao.nonce;
        payload.proof = cacao.proof;
        payload.issued_at = cacao.issued_at;
        payload.not_before = cacao.not_before;
        payload.expiration = cacao.expiration;
        payload.facts = cacao.facts;
        payload.sign(algorithm, signature)
    }
}

fn match_alg<const E: u64>(a: Algorithm, s: Vec<u8>) -> Result<JoseSig<E>, Error> {
    Ok(match a {
        Algorithm::ES256 => JoseSig::Es256(Es256::new(
            s.try_into()
                .map_err(|v: Vec<u8>| Error::IncorrectSignatureLength(v.len(), 64))?,
        )),
        Algorithm::EdDSA => JoseSig::Ed25519(Ed25519::new(
            s.try_into()
                .map_err(|v: Vec<u8>| Error::IncorrectSignatureLength(v.len(), 64))?,
        )),
        Algorithm::RS256 => JoseSig::Rsa256(Rsa256::new(s)),
        Algorithm::RS512 => JoseSig::Rsa512(Rsa512::new(s)),
        Algorithm::ES256K => JoseSig::Es256K(Es256K::new(
            s.try_into()
                .map_err(|v: Vec<u8>| Error::IncorrectSignatureLength(v.len(), 64))?,
        )),
        a => return Err(Error::UnsupportedAlgorithm(a)),
    })
}

#[async_trait]
impl<NB, R, F> CacaoVerifier<UcanSignature, UcanFacts<F>, NB> for R
where
    R: DIDResolver,
    F: Send + Sync + for<'a> Deserialize<'a> + Serialize + Clone,
    NB: Send + Sync + for<'a> Deserialize<'a> + Serialize + Clone,
{
    type Error = Error;

    async fn verify(&self, cacao: &UcanCacao<F, NB>) -> Result<(), Self::Error> {
        let ucan = Ucan::<F, NB>::from(cacao.clone()).encode_as_canonicalized_jwt()?;
        Ucan::<F, NB>::decode_and_verify(&ucan, self).await?;
        Ok(())
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
