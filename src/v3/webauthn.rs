use super::{
    payload::{BorrowedPayload, Payload},
    version::Version3,
    Cacao, CacaoVerifier,
};
use async_trait::async_trait;
use libipld::cid::{
    multihash::{Code, MultihashDigest},
    Cid, Error as CidError,
};
use multidid::MultiDid;
use serde::{Deserialize, Serialize};
use serde_ipld_dagcbor::EncodeError;
use serde_json::Value;
use ssi_dids::did_resolve::DIDResolver;
use ssi_jws::verify_bytes;
use ssi_ucan::util::get_verification_key;
use std::collections::TryReserveError;
use varsig::common::{
    webauthn::{try_from_base64url, Error as WebAuthnError},
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
    ClientDataParse(#[from] serde_json::Error),
    #[error(transparent)]
    AuthenticatorDataParse(#[from] WebAuthnError),
    #[error(transparent)]
    InvalidCid(#[from] CidError),
    #[error("Client Data Challenge does not match Payload")]
    ChallengeMismatch,
    #[error("Invalid Multihash Code: {0}")]
    InvalidMultihash(u64),
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<NB, R, F> CacaoVerifier<Version3, PasskeySig<DAG_CBOR_ENCODING>, F, NB> for &R
where
    R: DIDResolver,
    F: Send + Sync + for<'a> Deserialize<'a> + Serialize,
    NB: Send + Sync + for<'a> Deserialize<'a> + Serialize,
{
    type Error = Error;

    async fn verify(&self, cacao: &WebauthnCacao<F, NB>) -> Result<(), Error> {
        // extract webauthn client data from signature
        let client_data = cacao.signature.sig().as_ref().parse_client_data()?;
        // get Cid from client data
        let challenge = try_from_base64url(&client_data.challenge)
            .map(|v| Cid::read_bytes(v.as_slice()))
            .ok_or(CidError::ParsingError)??;
        // get original signed payload
        let payload = serde_ipld_dagcbor::to_vec(&BorrowedPayload::from(cacao))?;
        // verify Cid matches payload
        if challenge
            != Cid::new_v1(
                DAG_CBOR_ENCODING,
                Code::try_from(challenge.hash().code())
                    .map_err(|_| Error::InvalidMultihash(challenge.hash().code()))?
                    .digest(&payload),
            )
        {
            return Err(Error::ChallengeMismatch);
        }

        // get verification key from issuer DID
        let key = get_verification_key(&cacao.issuer.to_string(), *self).await?;
        // verify signature
        verify_bytes(
            key.algorithm.ok_or(ssi_jws::Error::MissingCurve)?,
            &[
                cacao.signature.sig().as_ref().client_data(),
                cacao.signature.sig().as_ref().authenticator_data(),
            ]
            .concat(),
            &key,
            &cacao.signature.sig().as_ref().signature(),
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
    pub fn sign(self, sig: WebauthnSignature) -> WebauthnCacao<F, NB> {
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
}
