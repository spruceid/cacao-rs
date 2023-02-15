use super::CACAO;
use http::uri::Authority;
use iri_string::types::UriString;
use serde::{Deserialize, Serialize};
use serde_json::Value;
pub use siwe;
use siwe::{eip55, Message, TimeStamp, VerificationError as SVE, Version as SVersion};
use std::fmt::Debug;
use std::io::{Read, Seek, Write};
use thiserror::Error;
use time::OffsetDateTime;

pub type RecapCacao<NB = Value> = CACAO<RecapFacts, NB>;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecapFacts {
    #[serde(rename = "iat-z")]
    iat_time_zone: Option<String>,
    #[serde(rename = "nbf-z")]
    nbf_time_zone: Option<String>,
    #[serde(rename = "nbf-z")]
    exp_time_zone: Option<String>,
    domain: Authority,
    statement: Option<String>,
    #[serde(rename = "request-id")]
    request_id: Option<String>,
    resources: Vec<UriString>,
}
