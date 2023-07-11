use libipld::cid::Cid;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use ucan_capabilities_object::Capabilities;

pub mod either;
pub mod recap_cacao;
pub mod ucan_cacao;

use multidid::MultiDid;
use varsig::{VarSig, VarSigTrait};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Cacao<S, F, NB> {
    #[serde(rename = "iss")]
    issuer: MultiDid,
    #[serde(rename = "aud")]
    audience: MultiDid,
    #[serde(rename = "s")]
    signature: S,
    #[serde(rename = "v")]
    version: String,
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
    #[serde(rename = "fct", skip_serializing_if = "Option::is_none", default)]
    facts: Option<F>,
}

pub trait CacaoProfile {
    type Signature: VarSigTrait;
    type Facts: Serialize + for<'d> Deserialize<'d>;
}

#[cfg(test)]
pub mod tests {
    use super::*;
}
