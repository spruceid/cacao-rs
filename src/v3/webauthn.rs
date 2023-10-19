use super::{Cacao, CacaoVerifier, Flattener};
use async_trait::async_trait;
use libipld::cid::{
    multihash::{Code, Multihash, MultihashDigest},
    Cid,
};
use multidid::MultiDid;
use serde::{de::Deserializer, ser::Serializer, Deserialize, Serialize};
use serde_ipld_dagcbor::EncodeError;
use serde_json::Value;
use ssi_dids::did_resolve::DIDResolver;
use ssi_jws::verify_bytes;
use ssi_ucan::util::get_verification_key;
use std::collections::{BTreeMap, TryReserveError};
use ucan_capabilities_object::Capabilities;
use varsig::common::{
    webauthn::{get_challenge_hash, Error as WebAuthnError},
    PasskeySig, DAG_CBOR_ENCODING,
};
use varsig::VarSig;

pub type WebauthnSignature = PasskeySig<DAG_CBOR_ENCODING>;
pub type WebauthnCacao<F = BTreeMap<String, Value>, NB = Value> =
    Cacao<WebauthnVersion, WebauthnSignature, F, NB>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    MultididParse(#[from] multidid::ParseErr),
    #[error(transparent)]
    DID(#[from] ssi_dids::Error),
    #[error(transparent)]
    JWS(#[from] ssi_jws::Error),
    #[error(transparent)]
    Encode(#[from] EncodeError<TryReserveError>),
    #[error(transparent)]
    WebauthnSig(#[from] WebAuthnError<DAG_CBOR_ENCODING>),
    #[error(transparent)]
    Multihash(#[from] libipld::cid::multihash::Error),
    #[error("Client Data Challenge does not match Payload")]
    ChallengeMismatch,
    #[error("Invalid Multihash Code: {0}")]
    InvalidMultihash(u64),
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<NB, R, F> CacaoVerifier<WebauthnCacao<F, NB>> for &R
where
    R: DIDResolver,
    F: Send + Sync + for<'a> Deserialize<'a> + Serialize,
    NB: Send + Sync + for<'a> Deserialize<'a> + Serialize,
{
    type Error = Error;

    async fn verify(&self, cacao: &WebauthnCacao<F, NB>) -> Result<(), Error> {
        // extract webauthn client data from signature
        let client_data = cacao
            .signature
            .sig()
            .parse_client_data()
            .map_err(|e| Error::WebauthnSig(e.into()))?;
        // get hash from client data
        let challenge = get_challenge_hash(&client_data)?;
        // verify hash matches payload
        if challenge
            != BorrowedPayload::from(cacao).get_webauthn_challenge_hash(Some(
                Code::try_from(challenge.code())
                    .map_err(|_| Error::InvalidMultihash(challenge.code()))?,
            ))?
        {
            return Err(Error::ChallengeMismatch);
        }

        // get verification key from issuer DID
        let key = get_verification_key(&cacao.issuer.to_string(), *self).await?;
        // verify signature
        verify_bytes(
            key.algorithm.ok_or(ssi_jws::Error::MissingCurve)?,
            &[
                Code::Sha2_256
                    .digest(cacao.signature.sig().client_data())
                    .digest(),
                cacao.signature.sig().authenticator_data(),
            ]
            .concat(),
            &key,
            cacao.signature.sig().signature().bytes(),
        )?;

        Ok(())
    }
}

impl<F, NB> WebauthnCacao<F, NB> {
    pub fn builder(audience: MultiDid) -> Payload<F, NB> {
        Payload::new(audience)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Eq, Hash)]
#[serde(deny_unknown_fields)]
pub struct Payload<F, NB> {
    #[serde(rename = "aud")]
    audience: MultiDid,
    #[serde(rename = "v")]
    version: WebauthnVersion,
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
}

impl<F, NB> Payload<F, NB> {
    pub fn new(audience: MultiDid) -> Self {
        Self {
            audience,
            version: WebauthnVersion,
            attenuations: Capabilities::default(),
            nonce: None,
            proof: None,
            issued_at: None,
            not_before: None,
            expiration: None,
            facts: None,
        }
    }

    pub fn capabilities<M>(&mut self, f: M) -> &mut Self
    where
        M: FnOnce(&mut Capabilities<NB>) -> Capabilities<NB>,
    {
        self.attenuations = f(&mut self.attenuations);
        self
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

    pub fn sign_webauthn(self, issuer: MultiDid, sig: WebauthnSignature) -> WebauthnCacao<F, NB> {
        Cacao {
            issuer,
            audience: self.audience,
            version: WebauthnVersion,
            attenuations: self.attenuations,
            nonce: self.nonce,
            proof: self.proof,
            issued_at: self.issued_at,
            not_before: self.not_before,
            expiration: self.expiration,
            facts: self.facts.map(|f| Flattener { f }),
            signature: VarSig::new(sig),
        }
    }

    pub fn get_webauthn_challenge_hash(
        &self,
        hash: Option<Code>,
    ) -> Result<Multihash, EncodeError<TryReserveError>>
    where
        F: Serialize,
        NB: Serialize,
    {
        BorrowedPayload::from(self).get_webauthn_challenge_hash(hash)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Eq, Hash)]
pub(crate) struct BorrowedPayload<'a, F, NB> {
    #[serde(rename = "aud")]
    audience: &'a MultiDid,
    #[serde(rename = "v")]
    version: WebauthnVersion,
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
    facts: Option<&'a F>,
}

impl<'a, F, NB> BorrowedPayload<'a, F, NB> {
    pub fn get_webauthn_challenge_hash(
        &self,
        hash: Option<Code>,
    ) -> Result<Multihash, EncodeError<TryReserveError>>
    where
        F: Serialize,
        NB: Serialize,
    {
        Ok(match hash {
            Some(c) => c,
            None => Code::Sha2_256,
        }
        .digest(&serde_ipld_dagcbor::to_vec(&self)?))
    }
}

impl<'a, F, NB> From<&'a WebauthnCacao<F, NB>> for BorrowedPayload<'a, F, NB> {
    fn from(cacao: &'a WebauthnCacao<F, NB>) -> Self {
        Self {
            audience: &cacao.audience,
            version: WebauthnVersion,
            attenuations: &cacao.attenuations,
            nonce: &cacao.nonce,
            proof: &cacao.proof,
            issued_at: &cacao.issued_at,
            not_before: &cacao.not_before,
            expiration: &cacao.expiration,
            facts: cacao.facts.as_ref().map(|f| &f.f),
        }
    }
}

impl<'a, F, NB> From<&'a Payload<F, NB>> for BorrowedPayload<'a, F, NB> {
    fn from(payload: &'a Payload<F, NB>) -> Self {
        Self {
            audience: &payload.audience,
            version: WebauthnVersion,
            attenuations: &payload.attenuations,
            nonce: &payload.nonce,
            proof: &payload.proof,
            issued_at: &payload.issued_at,
            not_before: &payload.not_before,
            expiration: &payload.expiration,
            facts: payload.facts.as_ref(),
        }
    }
}
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug, Default)]
pub struct WebauthnVersion;

impl Serialize for WebauthnVersion {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str("wan3")
    }
}

impl<'de> Deserialize<'de> for WebauthnVersion {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        if s == "wan3" {
            Ok(Self)
        } else {
            Err(serde::de::Error::custom("invalid version"))
        }
    }
}
