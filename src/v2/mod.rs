use std::fmt::Debug;

use async_trait::async_trait;
use iri_string::types::UriString;
use libipld::cid::Cid;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_with::{serde_as, DeserializeFromStr, SerializeDisplay};
use std::collections::BTreeMap;

pub mod multidid;
pub mod recap_cacao;
pub mod varsig;
pub mod version;

use multidid::MultiDID;
use varsig::VarSig;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CACAO<F = BTreeMap<String, Value>, NB = Value> {
    #[serde(rename = "iss")]
    issuer: MultiDID,
    #[serde(rename = "aud")]
    audience: MultiDID,
    #[serde(rename = "s")]
    signature: VarSig,
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
    facts: F,
}

#[cfg(test)]
pub mod tests {
    use super::*;
}
