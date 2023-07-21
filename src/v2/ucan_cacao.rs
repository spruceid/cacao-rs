use super::{Cacao, Verifier};
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

pub type UcanCacao<NB = Value> = Cacao<JoseSig<DAG_JSON_ENCODING>, BTreeMap<String, Value>, NB>;

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

impl<NB> TryFrom<Ucan<Value, NB>> for UcanCacao<NB> {
    type Error = Error;
    fn try_from(ucan: Ucan<Value, NB>) -> Result<Self, Self::Error> {
        let (header, payload, signature) = ucan.into_inner();
        Ok(Self {
            issuer: MultiDid::from_str(&payload.issuer)?,
            audience: MultiDid::from_str(&payload.audience)?,
            signature: VarSig::new(match_alg(header.algorithm, signature)?),
            version: "0.2.0".to_string(),
            attenuations: payload.capabilities,
            nonce: payload.nonce,
            proof: payload.proof,
            issued_at: payload.issued_at,
            not_before: payload.not_before,
            expiration: payload.expiration,
            facts: payload.facts,
        })
    }
}

impl<NB> From<UcanCacao<NB>> for Ucan<Value, NB> {
    fn from(cacao: UcanCacao<NB>) -> Self {
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
        payload.sign(todo!(), signature)
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
impl<NB, T> Verifier<NB, JoseSig<DAG_JSON_ENCODING>> for T
where
    T: DIDResolver,
    NB: Send + Sync + Serialize + for<'d> Deserialize<'d>,
{
    type Facts = BTreeMap<String, Value>;
    type Error = Error;
    async fn verify(&self, cacao: &UcanCacao<NB>) -> Result<(), Self::Error> {
        let ucan = Ucan::<Value, NB>::from(*cacao.clone()).encode_as_canonicalized_jwt()?;
        Ucan::<Value, NB>::decode_and_verify(&ucan, self).await?;
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
