use super::{Cacao, CacaoProfile};
use multidid::MultiDid;
use serde_json::Value;
use ssi_jwk::Algorithm;
use ssi_ucan::Ucan;
use varsig::{
    common::{Ed25519, Es256, Es256K, JoseSig, Rsa256, Rsa512, DAG_JSON_ENCODING},
    VarSig,
};

pub type UcanCacao<F = Value, NB = Value> = Cacao<JoseCommon<DAG_JSON_ENCODING>, F, NB>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Unsupported Algorithm: {0}")]
    UnsupportedAlgorithm(Algorithm),
    #[error("Incorrect Signature Length: recieved {0}, expected {1}")]
    IncorrectSignatureLength(usize, usize),
    #[error("Missing Version Header")]
    MissingVersionHeader,
}

impl<F, NB> TryFrom<Ucan<F, NB>> for UcanCacao<F, NB> {
    type Error = Error;
    fn try_from(ucan: Ucan<F, NB>) -> Result<Self, Self::Error> {
        let (header, payload, signature) = ucan.into_inner();
        Ok(Self {
            issuer: MultiDid::from_str(payload.issuer)?,
            audience: MultiDid::from_str(payload.audience)?,
            signature: VarSig::new(match_alg(header.alg, ucan.signature)?),
            version: header
                .additional_parameters
                .get("ucv")
                .ok_or_else(|| Error::MissingVersionHeader)?,
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

pub struct UcanCacaoProfile;

impl CacaoProfile for UcanCacaoProfile {
    type Signature = JoseCommon<DAG_JSON_ENCODING>;
    type Facts = Value;
}
