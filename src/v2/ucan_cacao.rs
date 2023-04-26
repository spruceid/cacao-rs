use super::CacaoProfile;
use serde_json::Value;
use ssi_jwk::Algorithm;
use ssi_ucan::Ucan;
use varsig::common::{JoseCommon, DAG_JSON_ENCODING};

pub type UcanCacao<F = Value, NB = Value> = Cacao<JoseCommon<DAG_JSON_ENCODING>, F, NB>;

#[derive(thiserror::Error, Debug)]
pub enum Error {}

impl<F, NB> TryFrom<Ucan<F, NB>> for UcanCacao<F, NB> {
    type Error = Error;
    fn try_from(ucan: Ucan<F, NB>) -> Result<Self, Self::Error> {
        Ok(Self {
            issuer: MultiDid::from_str(ucan.payload.issuer)?,
            audience: MultiDid::from_str(ucan.payload.audience)?,
            signature: match ucan.header.algorithm {
                Algorithm::Es256 =>
            },
            version: ucan
                .header
                .additional_parameters
                .get("ucv")
                .ok_or_else(|| todo!()),
            attenuations: ucan.payload.capabilities,
            nonce: ucan.payload.nonce,
            proof: ucan.payload.proof,
            issued_at: ucan.payload.issued_at,
            not_before: ucan.payload.not_before,
            expiration: ucan.payload.expiration,
            facts: ucan.payload.facts,
        })
    }
}

pub struct UcanCacaoProfile;

impl CacaoProfile for UcanCacaoProfile {
    type Signature = JoseCommon<RAW_ENCODING>;
    type Facts = Value;
}
