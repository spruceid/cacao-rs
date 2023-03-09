use std::fmt::Debug;

use async_trait::async_trait;
use iri_string::types::UriString;
use libipld::cid::Cid;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_with::{serde_as, serde_conv, DeserializeFromStr, SerializeDisplay};
use std::collections::BTreeMap;

pub mod recap_cacao;

use multidid::MultiDid;
use varsig::{SignatureHeader, VarSig};

#[serde_as]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CACAO<P: CacaoProfile, NB = Value> {
    #[serde(rename = "iss")]
    issuer: MultiDid,
    #[serde(rename = "aud")]
    audience: MultiDid,
    #[serde(rename = "s")]
    signature: VarSig<P::Signature>,
    #[serde(rename = "v")]
    version: String,
    #[serde(rename = "att")]
    attenuations: BTreeMap<UriString, BTreeMap<String, Vec<BTreeMap<String, NB>>>>,
    #[serde(rename = "nnc")]
    nonce: String,
    #[serde(rename = "prf", skip_serializing_if = "Vec::is_empty", default)]
    proof: Vec<Cid>,
    #[serde(rename = "iat")]
    issued_at: Option<u64>,
    #[serde(rename = "nbf")]
    not_before: Option<u64>,
    #[serde(rename = "exp")]
    expiration: Option<u64>,
    #[serde(rename = "fct")]
    facts: P::Facts,
}

pub trait CacaoProfile {
    type Signature: SignatureHeader;
    type Facts: for<'d> Deserialize<'d> + Serialize + Clone + Debug;
}

serde_conv!(
    MultiDidToBytes,
    MultiDid,
    |did: &MultiDid| did.to_vec(),
    |value: &[u8]| MultiDid::from_bytes(value)
);

#[cfg(test)]
pub mod tests {
    use super::*;
}
