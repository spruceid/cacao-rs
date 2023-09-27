use super::Cacao;
use libipld::{cid::Cid, Ipld};
use multidid::MultiDid;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use ucan_capabilities_object::Capabilities;
use varsig::VarSig;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Eq, Hash)]
#[serde(deny_unknown_fields)]
pub struct Payload<V, F, NB = Ipld> {
    #[serde(rename = "iss")]
    pub issuer: MultiDid,
    #[serde(rename = "aud")]
    pub audience: MultiDid,
    #[serde(rename = "v")]
    version: V,
    #[serde(rename = "att")]
    pub attenuations: Capabilities<NB>,
    #[serde(rename = "nnc", skip_serializing_if = "Option::is_none", default)]
    pub nonce: Option<String>,
    #[serde(rename = "prf", skip_serializing_if = "Option::is_none", default)]
    pub proof: Option<Vec<Cid>>,
    #[serde(rename = "iat", skip_serializing_if = "Option::is_none", default)]
    pub issued_at: Option<u64>,
    #[serde(rename = "nbf", skip_serializing_if = "Option::is_none", default)]
    pub not_before: Option<u64>,
    #[serde(rename = "exp", skip_serializing_if = "Option::is_none", default)]
    pub expiration: Option<u64>,
    #[serde(
        rename = "fct",
        skip_serializing_if = "Option::is_none",
        default = "Option::default"
    )]
    pub facts: Option<F>,
}

impl<V, F, NB> Payload<V, F, NB> {
    pub fn capabilities(&mut self) -> &mut Capabilities<NB> {
        &mut self.attenuations
    }

    pub fn nonce(&mut self, nonce: String) -> &mut Self {
        self.nonce = Some(nonce);
        self
    }

    pub fn proof(&mut self, proof: Vec<Cid>) -> &mut Self {
        self.proof = Some(proof);
        self
    }

    pub fn issued_at(&mut self, iat: u64) -> &mut Self {
        self.issued_at = Some(iat);
        self
    }

    pub fn not_before(&mut self, nbf: u64) -> &mut Self {
        self.not_before = Some(nbf);
        self
    }

    pub fn expiration(&mut self, exp: u64) -> &mut Self {
        self.expiration = Some(exp);
        self
    }

    pub fn facts(&mut self, facts: F) -> &mut Self {
        self.facts = Some(facts);
        self
    }

    pub fn sign<S>(self, sig: S) -> Cacao<V, S, F, NB> {
        Cacao {
            issuer: self.issuer,
            audience: self.audience,
            version: self.version,
            attenuations: self.attenuations,
            nonce: self.nonce,
            proof: self.proof,
            issued_at: self.issued_at,
            not_before: self.not_before,
            expiration: self.expiration,
            facts: self.facts,
            signature: VarSig::new(sig),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Eq, Hash)]
#[serde(deny_unknown_fields)]
pub(crate) struct BorrowedPayload<'a, V, F, NB> {
    #[serde(rename = "iss")]
    issuer: &'a MultiDid,
    #[serde(rename = "aud")]
    audience: &'a MultiDid,
    #[serde(rename = "v")]
    version: &'a V,
    #[serde(rename = "att")]
    attenuations: &'a Capabilities<NB>,
    #[serde(rename = "nnc", skip_serializing_if = "Option::is_none", default)]
    nonce: &'a Option<String>,
    #[serde(rename = "prf", skip_serializing_if = "Option::is_none", default)]
    proof: &'a Option<Vec<Cid>>,
    #[serde(rename = "iat", skip_serializing_if = "Option::is_none", default)]
    issued_at: &'a Option<u64>,
    #[serde(rename = "nbf", skip_serializing_if = "Option::is_none", default)]
    not_before: &'a Option<u64>,
    #[serde(rename = "exp", skip_serializing_if = "Option::is_none", default)]
    expiration: &'a Option<u64>,
    #[serde(
        rename = "fct",
        skip_serializing_if = "Option::is_none",
        default = "Option::default"
    )]
    facts: &'a Option<F>,
}

impl<'a, V, S, F, NB> From<&'a Cacao<V, S, F, NB>> for BorrowedPayload<'a, V, F, NB> {
    fn from(cacao: &'a Cacao<V, S, F, NB>) -> Self {
        Self {
            issuer: &cacao.issuer,
            audience: &cacao.audience,
            version: &cacao.version,
            attenuations: &cacao.attenuations,
            nonce: &cacao.nonce,
            proof: &cacao.proof,
            issued_at: &cacao.issued_at,
            not_before: &cacao.not_before,
            expiration: &cacao.expiration,
            facts: &cacao.facts,
        }
    }
}

impl<'a, V, F, NB> From<&'a Payload<V, F, NB>> for BorrowedPayload<'a, V, F, NB> {
    fn from(payload: &'a Payload<V, F, NB>) -> Self {
        Self {
            issuer: &payload.issuer,
            audience: &payload.audience,
            version: &payload.version,
            attenuations: &payload.attenuations,
            nonce: &payload.nonce,
            proof: &payload.proof,
            issued_at: &payload.issued_at,
            not_before: &payload.not_before,
            expiration: &payload.expiration,
            facts: &payload.facts,
        }
    }
}
