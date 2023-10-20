use super::{payload::Payload, Cacao, CacaoVerifier, Flattener};
use async_trait::async_trait;
use multidid::MultiDid;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use ssi_dids::did_resolve::DIDResolver;
use ssi_ucan::{
    jose::{self, Signature, VerificationError},
    jwt,
    version::SemanticVersion,
    Payload as UcanPayload, Ucan,
};
use std::collections::BTreeMap;
use std::str::FromStr;
use varsig::{
    common::{Ed25519, Es256, Es256K, Es512, JoseSig, Rsa256, Rsa512, DAG_JSON_ENCODING},
    VarSig,
};

pub type UcanSignature = JoseSig<DAG_JSON_ENCODING>;
pub type UcanCacao<F = BTreeMap<String, Value>, NB = Value> =
    Cacao<SemanticVersion, UcanSignature, F, NB>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    MultididParse(#[from] multidid::ParseErr),
    #[error(transparent)]
    Verification(#[from] VerificationError<jose::Error>),
}

impl From<jwt::EncodeError> for Error {
    fn from(e: jwt::EncodeError) -> Self {
        Self::Verification(e.into())
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<NB, R, F> CacaoVerifier<UcanCacao<BTreeMap<String, F>, NB>> for &R
where
    R: DIDResolver,
    F: Send + Sync + for<'a> Deserialize<'a> + Serialize + Clone,
    NB: Send + Sync + for<'a> Deserialize<'a> + Serialize + Clone,
{
    type Error = Error;

    async fn verify(&self, cacao: &UcanCacao<BTreeMap<String, F>, NB>) -> Result<(), Error> {
        let ucan = Ucan::<F, NB, Signature>::from(cacao.clone()).encode()?;
        Ucan::<F, NB, Signature>::decode_and_verify_jwt(&ucan, *self, None).await?;
        Ok(())
    }
}

impl<F, NB> TryFrom<Ucan<F, NB, Signature>> for UcanCacao<BTreeMap<String, F>, NB> {
    type Error = Error;
    fn try_from(ucan: Ucan<F, NB, Signature>) -> Result<Self, Self::Error> {
        let (payload, signature) = ucan.into_inner();
        Ok(Self {
            issuer: MultiDid::from_str(&payload.issuer)?,
            audience: MultiDid::from_str(&payload.audience)?,
            version: SemanticVersion,
            attenuations: payload.capabilities,
            nonce: payload.nonce,
            proof: payload.proof,
            issued_at: payload.issued_at,
            not_before: payload.not_before,
            expiration: payload.expiration,
            facts: payload.facts.map(|f| Flattener { f }),
            signature: VarSig::new(match signature {
                Signature::ES256(sig) => JoseSig::Es256(Es256::new(sig)),
                Signature::ES512(sig) => JoseSig::Es512(Es512::new(sig)),
                Signature::EdDSA(sig) => JoseSig::EdDSA(Ed25519::new(sig)),
                Signature::RS256(sig) => JoseSig::Rsa256(Rsa256::new(sig)),
                Signature::RS512(sig) => JoseSig::Rsa512(Rsa512::new(sig)),
                Signature::ES256K(sig) => JoseSig::Es256K(Es256K::new(sig)),
            }),
        })
    }
}

impl<F, NB> From<UcanCacao<BTreeMap<String, F>, NB>> for Ucan<F, NB, Signature> {
    fn from(cacao: UcanCacao<BTreeMap<String, F>, NB>) -> Self {
        let signature = match cacao.signature.into_inner() {
            JoseSig::EdDSA(s) => Signature::EdDSA(s.into_inner()),
            JoseSig::Es256(s) => Signature::ES256(s.into_inner()),
            JoseSig::Es512(s) => Signature::ES512(s.into_inner()),
            JoseSig::Es256K(s) => Signature::ES256K(s.into_inner()),
            JoseSig::Rsa256(s) => Signature::RS256(s.into_inner()),
            JoseSig::Rsa512(s) => Signature::RS512(s.into_inner()),
        };
        let mut payload = UcanPayload::new(cacao.issuer.to_string(), cacao.audience.to_string());
        payload.capabilities = cacao.attenuations;
        payload.nonce = cacao.nonce;
        payload.proof = cacao.proof;
        payload.issued_at = cacao.issued_at;
        payload.not_before = cacao.not_before;
        payload.expiration = cacao.expiration;
        payload.facts = cacao.facts.map(|f| f.f);
        payload.sign(signature)
    }
}

impl<F, NB> UcanCacao<F, NB> {
    pub fn builder(iss: MultiDid, aud: MultiDid) -> Payload<SemanticVersion, F, NB> {
        Payload::new(iss, aud, SemanticVersion)
    }
}

impl<F, NB> Payload<SemanticVersion, F, NB> {
    pub fn sign(self, sig: UcanSignature) -> UcanCacao<F, NB> {
        Cacao {
            issuer: self.issuer,
            audience: self.audience,
            version: SemanticVersion,
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
}
