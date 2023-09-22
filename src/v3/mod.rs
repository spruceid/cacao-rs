use async_trait::async_trait;
use libipld::{cid::Cid, Ipld};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use ucan_capabilities_object::Capabilities;

pub mod common;
pub mod recap_cacao;
pub mod ucan_cacao;

pub use multidid;
use multidid::MultiDid;
pub use varsig;
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
    #[serde(
        rename = "fct",
        skip_serializing_if = "Option::is_none",
        default = "Option::default"
    )]
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

    pub fn facts(&self) -> Option<&F> {
        self.facts.as_ref()
    }

    pub fn signature(&self) -> &VarSig<S> {
        &self.signature
    }

    pub fn valid_at_time(&self, time: u64, skew: Option<u64>) -> bool {
        self.expiration
            .map_or(true, |exp| time < exp + skew.unwrap_or(0))
            && self
                .not_before
                .map_or(true, |nbf| time >= nbf - skew.unwrap_or(0))
            && self.issued_at.map_or(true, |iat| {
                self.not_before.map_or(true, |nbf| nbf < iat)
                    && self.expiration.map_or(true, |exp| iat < exp)
            })
    }

    pub async fn verify<V>(&self, verifier: &V) -> Result<(), V::Error>
    where
        V: CacaoVerifier<S, F, NB>,
        NB: Send + Sync,
    {
        verifier.verify(self).await
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait CacaoVerifier<S, F, NB> {
    type Error: std::error::Error;

    async fn verify(&self, cacao: &Cacao<S, F, NB>) -> Result<(), Self::Error>;
}
