use super::{payload::Payload, version::Version3, Cacao, CacaoVerifier};
use async_trait::async_trait;
use libipld::cid::{
    multihash::{Code, Multihash, MultihashDigest},
    Cid,
};
use multidid::MultiDid;
use serde::{Deserialize, Serialize};
use serde_ipld_dagcbor::EncodeError;
use serde_json::Value;
use ssi_dids::did_resolve::DIDResolver;
use ssi_jws::verify_bytes;
use ssi_ucan::util::get_verification_key;
use std::collections::TryReserveError;
use ucan_capabilities_object::Capabilities;
use varsig::common::{
    webauthn::{get_challenge_hash, Error as WebAuthnError},
    PasskeySig, DAG_CBOR_ENCODING,
};
use varsig::VarSig;

pub type WebauthnSignature = PasskeySig<DAG_CBOR_ENCODING>;
pub type WebauthnCacao<F = Value, NB = Value> = Cacao<Version3, WebauthnSignature, F, NB>;

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
impl<NB, R, F> CacaoVerifier<Version3, WebauthnSignature, F, NB> for &R
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
        // get Cid from client data
        let challenge = get_challenge_hash(&client_data)?;
        // verify Cid matches payload
        if challenge
            != SigningPayload::from(cacao).get_hash(Some(
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
    pub fn builder(issuer: MultiDid, audience: MultiDid) -> Payload<Version3, F, NB> {
        Payload::new(issuer, audience, Version3)
    }
}

impl<F, NB> Payload<Version3, F, NB> {
    pub fn sign_webauthn(self, sig: WebauthnSignature) -> WebauthnCacao<F, NB> {
        Cacao {
            issuer: self.issuer,
            audience: self.audience,
            version: Version3,
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

    pub fn get_webauthn_challenge_hash(
        &self,
        hash: Option<Code>,
    ) -> Result<Multihash, EncodeError<TryReserveError>>
    where
        F: Serialize,
        NB: Serialize,
    {
        SigningPayload::from(self).get_hash(hash)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Eq, Hash)]
struct SigningPayload<'a, F, NB> {
    #[serde(rename = "aud")]
    audience: &'a MultiDid,
    #[serde(rename = "v")]
    version: Version3,
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

impl<'a, F, NB> SigningPayload<'a, F, NB> {
    pub fn get_hash(&self, hash: Option<Code>) -> Result<Multihash, EncodeError<TryReserveError>>
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

impl<'a, F, NB> From<&'a WebauthnCacao<F, NB>> for SigningPayload<'a, F, NB> {
    fn from(cacao: &'a WebauthnCacao<F, NB>) -> Self {
        Self {
            audience: &cacao.audience,
            version: Version3,
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

impl<'a, F, NB> From<&'a Payload<Version3, F, NB>> for SigningPayload<'a, F, NB> {
    fn from(payload: &'a Payload<Version3, F, NB>) -> Self {
        Self {
            audience: &payload.audience,
            version: Version3,
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
