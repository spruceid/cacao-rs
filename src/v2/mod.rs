use libipld::{cid::Cid, ipld::Ipld};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::fmt::Debug;
use ucan_capabilities_object::Capabilities;

pub mod either;
pub mod recap_cacao;
pub mod ucan_cacao;

pub mod serde_util;

use multidid::MultiDid;
use serde_util::{MultiDidAsBytes, VarSigAsBytes};
use varsig::{VarSig, VarSigTrait};

#[serde_as]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Cacao<S: VarSigTrait, F, NB> {
    #[serde_as(as = "MultiDidAsBytes")]
    #[serde(rename = "iss")]
    issuer: MultiDid,
    #[serde_as(as = "MultiDidAsBytes")]
    #[serde(rename = "aud")]
    audience: MultiDid,
    #[serde_as(as = "VarSigAsBytes")]
    #[serde(rename = "s")]
    signature: VarSig<S>,
    #[serde(rename = "v")]
    version: String,
    #[serde(rename = "att")]
    attenuations: Capabilities<NB>,
    #[serde(rename = "nnc", skip_serializing_if = "Option::is_none")]
    nonce: Option<String>,
    #[serde(rename = "prf", skip_serializing_if = "Vec::is_empty", default)]
    proof: Vec<Cid>,
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
