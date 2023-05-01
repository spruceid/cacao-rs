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
use time::UtcOffset;
use varsig::{
    common::{Ethereum, EIP191_ENCODING},
    VarSig,
};

pub type RecapCacao<NB = Value> = Cacao<Ethereum<EIP191_ENCODING>, RecapFacts, NB>;

#[serde_as]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecapFacts {
    #[serde(rename = "iat-z")]
    iat_time_zone: Option<UtcOffset>,
    #[serde(rename = "nbf-z")]
    nbf_time_zone: Option<UtcOffset>,
    #[serde(rename = "nbf-z")]
    exp_time_zone: Option<UtcOffset>,
    #[serde(rename = "iat-n")]
    iat_nanos: Option<u32>,
    #[serde(rename = "nbf-n")]
    nbf_nanos: Option<u32>,
    #[serde(rename = "exp-n")]
    exp_nanos: Option<u32>,
    #[serde_as(as = "DisplayFromStr")]
    domain: Authority,
    statement: Option<String>,
    #[serde(rename = "request-id")]
    request_id: Option<String>,
    resources: Vec<UriString>,
}

#[derive(thiserror::Error, Debug)]
pub enum Error {}

impl<NB> TryFrom<(Message, Vec<u8>)> for RecapCacao<NB>
where
    NB: for<'d> Deserialize<'d>,
{
    type Error = Error;
    fn try_from((siwe, sig): (Message, Vec<u8>)) -> Result<Self, Self::Error> {
        let recap = Capability::<NB>::extract_and_verify(&siwe)?;
        let (issued_at, iat_time_zone, iat_nanos) = split_tz(Some(siwe.issued_at));
        let (not_before, nbf_time_zone, nbf_nanos) = split_tz(siwe.not_before);
        let (expiration, exp_time_zone, exp_nanos) = split_tz(siwe.expiration_time);
        let statement = siwe
            .statement
            .map(|s| s.get(0..(s.len() - recap.to_statement().len())));
        let (attenuations, proof) = recap.into_inner();
        Ok(Self {
            issuer: MultiDid::new(
                Method::Pkh(DidPkhTypes::Eip155(
                    (siwe.chain_id.to_string(), siwe.address).into(),
                )),
                None,
                None,
            ),
            audience: MultiDid::from_str(siwe.uri)?,
            signature: VarSig::new(Ethereum::sig.try_into()?),
            version: (siwe.version as u8).to_string(),
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
                iat_nanos,
                nbf_nanos,
                exp_nanos,
                domain: siwe.domain,
                request_id: siwe.request_id,
                resources: siwe.resources[0..-1],
                statement,
            }),
        })
    }
}

fn split_tz(t: Option<TimeStamp>) -> (Option<u64>, Option<UtcOffset>, Option<u32>) {
    match t {
        Some(t) => (
            Some(t.as_ref().unix_timestamp().into()),
            Some(t.offset()),
            Some(t.nanosecond()),
        ),
        None => (None, None, None),
    }
}

fn get_tz((unix, tz, nano): (Option<u64>, Option<UtcOffset>, Option<u32>)) -> Option<TimeStamp> {
    match (unix, tz, nano) {
        (Some(unix), Some(tz), Some(nano)) if nano < 1_000_000_000 => Some(
            TimeStamp::from_unix_timestamp(unix)
                .replace_offset(tz)
                .replace_nanosecond(nano)
                // lets just assume nano < 1000000000, we check before here
                .unwrap(),
        ),
        _ => None,
    }
}
