use super::Cacao;
use http::uri::Authority;
use iri_string::types::UriString;
use multidid::{DidPkhTypes, Method, MultiDid};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_with::{serde_as, DeserializeFromStr, DisplayFromStr, SerializeDisplay};
pub use siwe;
use siwe::{eip55, Message, TimeStamp, VerificationError as SVE, Version as SVersion};
use siwe_recap::Capability;
use std::fmt::Debug;
use std::io::{Read, Seek, Write};
use thiserror::Error;
use time::OffsetDateTime;
use varsig::common::{Ethereum, EIP191_ENCODING};

pub type RecapCacao<NB = Value> = Cacao<Ethereum<EIP191_ENCODING>, RecapFacts, NB>;

#[serde_as]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecapFacts {
    #[serde(rename = "iat-z")]
    iat_time_zone: Option<String>,
    #[serde(rename = "nbf-z")]
    nbf_time_zone: Option<String>,
    #[serde(rename = "nbf-z")]
    exp_time_zone: Option<String>,
    #[serde_as(as = "DisplayFromStr")]
    domain: Authority,
    statement: Option<String>,
    #[serde(rename = "request-id")]
    request_id: Option<String>,
    resources: Vec<UriString>,
}

#[derive(thiserror::Error, Debug)]
pub enum Error {}

impl<NB> TryFrom<(Message, Vec<u8>)> for RecapCacao<NB> {
    type Error = Error;
    fn try_from((siwe, sig): (Message, Vec<u8>)) -> Result<Self, Self::Error> {
        let recap = Capability::<NB>::extract_and_verify(&siwe)?.into_inner();
        let (issued_at, iat_time_zone) = siwe.issued_at.map(split_tz);
        let (not_before, nbf_time_zone) = siwe.not_before.map(split_tz);
        let (expiration, exp_time_zone) = siwe.expiration.map(split_tz);
        let statement = siwe
            .statement
            .map(|s| s.get(0..(s.len() - recap.to_statement().len())));
        let (attenuations, proof) = recap.into_inner();
        OK(Self {
            issuer: MultiDid::new(
                Method::Pkh(DidPkhTypes::Eip155((siwe.chain_id, siwe.address).into())),
                None,
                None,
            ),
            audience: MultiDid::from_str(siwe.uri)?,
            signature: VarSig::new(sig.try_into()?),
            version: siwe.version,
            attenuations,
            nonce: Some(siwe.nonce),
            proof,
            issued_at,
            not_before,
            expiration,
            facts: Some(RecapFacts {
                iat_time_zone,
                nbf_time_zone,
                exp_time_zone,
                domain: siwe.domain,
                request_id: siwe.request_id,
                resources: siwe.resources[0..-1],
                statement,
            }),
        })
    }
}

fn split_tz(t: TimeStamp) -> (u64, String) {
    todo!()
}
