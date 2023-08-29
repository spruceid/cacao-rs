use async_trait::async_trait;
use libipld::{cid::Cid, Ipld};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use ucan_capabilities_object::Capabilities;

pub mod either;
pub mod recap_cacao;
pub mod ucan_cacao;

use multidid::MultiDid;
use varsig::{VarSig, VarSigTrait};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Eq, Hash)]
#[serde(deny_unknown_fields)]
pub struct Cacao<S, F, NB = Ipld> {
    #[serde(rename = "iss")]
    issuer: MultiDid,
    #[serde(rename = "aud")]
    audience: MultiDid,
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
    #[serde(rename = "s", bound = "S: VarSigTrait")]
    signature: VarSig<S>,
}

impl<S, F, NB> Cacao<S, F, NB> {
    pub fn issuer(&self) -> &MultiDid {
        &self.issuer
    }

    pub fn audience(&self) -> &MultiDid {
        &self.audience
    }

    pub fn capabilities(&self) -> &Capabilities<NB> {
        &self.attenuations
    }

    pub fn nonce(&self) -> Option<&str> {
        self.nonce.as_deref()
    }

    pub fn proof(&self) -> Option<&[Cid]> {
        self.proof.as_deref()
    }

    pub fn issued_at(&self) -> Option<u64> {
        self.issued_at
    }

    pub fn not_before(&self) -> Option<u64> {
        self.not_before
    }

    pub fn expiration(&self) -> Option<u64> {
        self.expiration
    }

    fn facts(&self) -> Option<&F> {
        self.facts.as_ref()
    }

    fn signature(&self) -> &VarSig<S> {
        &self.signature
    }

    pub async fn verify<V>(&self, verifier: &V) -> Result<(), V::Error>
    where
        V: CacaoVerifier<S, F, NB>,
        NB: Send + Sync,
    {
        verifier.verify(self).await
    }
}

#[async_trait]
pub trait CacaoVerifier<S, F, NB> {
    type Error: std::error::Error;

    async fn verify(&self, cacao: &Cacao<S, F, NB>) -> Result<(), Self::Error>;
}

#[cfg(test)]
pub mod tests {
    use super::*;
}
