use siwe::TimeStamp;
use ssi::{
    did::DIDURL,
    vc::URI,
    zcap::{Delegation, Invocation},
};

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct DelProps {
    // exp
    pub expiration: Option<TimeStamp>,
    // nbf
    pub created: Option<TimeStamp>,
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct InvProps {
    // exp
    pub expiration: Option<TimeStamp>,
    // nbf
    pub created: Option<TimeStamp>,
    // aud
    pub invocation_target: String,
    // resources
    pub capability_action: Action,
}

pub type KeplerInvocation = Invocation<InvProps>;
pub type KeplerDelegation = Delegation<(), DelProps>;
