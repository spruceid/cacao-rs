use super::{Cacao, CacaoVerifier};
use async_trait::async_trait;
use http::uri::Authority;
use iri_string::types::UriString;
use multidid::{DidPkhTypes, Method, MultiDid};
use serde::{Deserialize, Serialize};
use serde_json::Value;
pub use siwe;
use siwe::{Message, TimeStamp};
pub use siwe_recap::Capability;
use std::{fmt::Debug, str::FromStr};
use time::{format_description::well_known::Rfc3339, OffsetDateTime, UtcOffset};
use varsig::{
    common::{Ethereum, EIP191_ENCODING},
    VarSig,
};

pub type RecapSignature = Ethereum<EIP191_ENCODING>;
pub type RecapCacao<NB = Value> = Cacao<RecapSignature, RecapFacts, NB>;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Eq, PartialOrd, Hash)]
#[serde(deny_unknown_fields)]
pub struct RecapFacts {
    #[serde(rename = "iat-z")]
    iat_info: String,
    #[serde(rename = "nbf-z")]
    nbf_info: Option<String>,
    #[serde(rename = "nbf-z")]
    exp_info: Option<String>,
    #[serde(
        serialize_with = "serialize_authority",
        deserialize_with = "deserialize_authority"
    )]
    domain: Authority,
    statement: Option<String>,
    #[serde(rename = "request-id")]
    request_id: Option<String>,
    resources: Vec<UriString>,
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    StatementVerification(#[from] siwe_recap::VerificationError),
    #[error(transparent)]
    MultididParse(#[from] multidid::ParseErr),
    #[error(transparent)]
    TimeConversion(#[from] time::error::Error),
    #[error("Expected did:pkh:eip155, found {0}")]
    IncorrectDidType(Method),
    #[error("Recap Issuer DIDs must not have a fragment or query parameters")]
    ExtraDidComponents,
    #[error("The 'facts' field is required for Recap Cacaos")]
    MissingFacts,
    #[error("Incorrect Version, expected '1', found: {0}")]
    IncorrectVersion(String),
    #[error("SIWE messages must have a nonce")]
    MissingNonce,
    #[error("SIWE messages must have a issuance timestamp")]
    MissingIat,
    #[error("UNIX timestamps must have associated timezone facts")]
    InconsistentTimeInfo,
    #[error(transparent)]
    MessageBuild(#[from] siwe_recap::EncodingError),
    #[error("Failed to parse aud URI: {0}")]
    AudUri(#[from] iri_string::validate::Error),
    #[error("Invalid Signature: {0}")]
    InvalidSignature(#[from] siwe::VerificationError),
}

impl<NB> TryFrom<(Message, [u8; 65])> for RecapCacao<NB>
where
    NB: for<'d> Deserialize<'d>,
{
    type Error = Error;
    fn try_from((siwe, sig): (Message, [u8; 65])) -> Result<Self, Self::Error> {
        let recap = Capability::<NB>::extract_and_verify(&siwe)?;
        let (issued_at, iat_info) = split_tz(siwe.issued_at);
        let (not_before, nbf_info) = match siwe.not_before.map(split_tz) {
            Some((nb, tz)) => (Some(nb), Some(tz)),
            None => (None, None),
        };
        let (expiration, exp_info) = match siwe.expiration_time.map(split_tz) {
            Some((exp, tz)) => (Some(exp), Some(tz)),
            None => (None, None),
        };
        let statement = siwe.statement.and_then(|s| {
            s.get(0..(s.len() - recap.as_ref().map(|r| r.to_statement().len()).unwrap_or(0)))
                .map(|s| s.to_string())
        });
        let (attenuations, proof) = recap
            .map(|r| r.into_inner())
            .unwrap_or((Default::default(), Vec::new()));
        let mut resources = siwe.resources;
        resources.pop();
        Ok(Self {
            issuer: MultiDid::new(
                Method::Pkh(DidPkhTypes::Eip155((siwe.chain_id, siwe.address).into())),
                None,
                None,
            ),
            audience: MultiDid::from_str(siwe.uri.as_str())?,
            version: (siwe.version as u8).to_string(),
            attenuations,
            nonce: Some(siwe.nonce),
            proof: Some(proof),
            issued_at: Some(issued_at),
            not_before,
            expiration,
            facts: Some(RecapFacts {
                iat_info,
                nbf_info,
                exp_info,
                domain: siwe.domain,
                request_id: siwe.request_id,
                resources,
                statement,
            }),
            signature: VarSig::new(Ethereum::new(sig)),
        })
    }
}

impl<NB> TryFrom<RecapCacao<NB>> for (Message, [u8; 65])
where
    NB: Serialize,
{
    type Error = Error;
    fn try_from(cacao: RecapCacao<NB>) -> Result<Self, Self::Error> {
        if cacao.issuer.fragment().is_some() || cacao.issuer.query().is_some() {
            return Err(Error::ExtraDidComponents);
        }
        let (chain_id, address) = match cacao.issuer.into_inner().0 {
            Method::Pkh(DidPkhTypes::Eip155(eip155)) => eip155.into_inner(),
            m => return Err(Error::IncorrectDidType(m)),
        };
        let facts = cacao.facts.ok_or(Error::MissingFacts)?;
        let mut cap = Capability::new().with_proofs(cacao.proof.unwrap_or_default().iter());
        for (resource, actions) in cacao.attenuations.into_inner() {
            cap.with_actions(resource, actions);
        }
        Ok((
            cap.build_message(Message {
                domain: facts.domain,
                address,
                statement: facts.statement,
                uri: cacao.audience.to_string().parse()?,
                version: cacao
                    .version
                    .parse()
                    .map_err(|_| Error::IncorrectVersion(cacao.version))?,
                chain_id,
                nonce: cacao.nonce.ok_or(Error::MissingNonce)?,
                issued_at: make_ts(cacao.issued_at.ok_or(Error::MissingIat)?, &facts.iat_info)?,
                expiration_time: match (cacao.expiration, facts.exp_info) {
                    (Some(exp), Some(zexp)) => Some(make_ts(exp, &zexp)?),
                    (None, None) => None,
                    _ => return Err(Error::InconsistentTimeInfo),
                },
                not_before: match (cacao.not_before, facts.nbf_info) {
                    (Some(nbf), Some(znbf)) => Some(make_ts(nbf, &znbf)?),
                    (None, None) => None,
                    _ => return Err(Error::InconsistentTimeInfo),
                },
                request_id: facts.request_id,
                resources: facts.resources,
            })?,
            cacao.signature.into_inner().into_inner(),
        ))
    }
}

fn split_tz(t: TimeStamp) -> (u64, String) {
    let unix = t.as_ref().unix_timestamp();
    let mut t_str = t.to_string();
    (
        // hmmm
        unix as u64,
        t_str
            // if its fractional, split on '.
            .find('.')
            // if not, split on 'Z' or 'z'
            .or_else(|| t_str.find('Z'))
            .or_else(|| t_str.find('z'))
            .map(|i| t_str.split_off(i))
            // this default should never actually happen
            // as long as TimeStamp serialises properly
            .unwrap_or(t.as_ref().offset().to_string()),
    )
}

fn make_ts(unix: u64, z: &str) -> Result<TimeStamp, time::error::Error> {
    // we need to get the serialisation of the date and time
    let odt = OffsetDateTime::from_unix_timestamp(unix as i64)?
        // by setting the offset to the same one in z
        .to_offset(UtcOffset::parse(
            if z.starts_with('.') {
                z.find('Z')
                    .or_else(|| z.find('z'))
                    .and_then(|i| z.get((i + 1)..))
                    .unwrap_or(z)
            } else {
                z
            },
            &Rfc3339,
        )?)
        .to_string();

    // then concat that serialisation with z to get the original timestamp
    TimeStamp::from_str(
        &[
            odt.find('.')
                .or_else(|| odt.find('Z'))
                .or_else(|| odt.find('z'))
                .and_then(|i| odt.get(..i))
                .unwrap_or(&odt),
            z,
        ]
        .concat(),
    )
}

fn serialize_authority<S>(authority: &Authority, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(authority.as_str())
}

fn deserialize_authority<'de, D>(deserializer: D) -> Result<Authority, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    Authority::from_str(&s).map_err(serde::de::Error::custom)
}

#[derive(Default)]
pub struct RecapVerify(());

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<NB> CacaoVerifier<RecapSignature, RecapFacts, NB> for RecapVerify
where
    NB: Send + Sync + Serialize + Clone,
{
    type Error = Error;

    async fn verify(&self, cacao: &RecapCacao<NB>) -> Result<(), Self::Error> {
        let (message, signature) = <(Message, [u8; 65])>::try_from(cacao.clone())?;
        message.verify_eip191(&signature)?;
        Ok(())
    }
}
