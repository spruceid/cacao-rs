use serde_with::{DeserializeFromStr, SerializeDisplay};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, SerializeDisplay, DeserializeFromStr)]
pub struct Version3;

impl std::fmt::Display for Version3 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "3")
    }
}

#[derive(Error, Debug, Copy, PartialEq)]
pub struct VersionErr;

impl std::str::FromStr for Version3 {
    type Err = VersionErr;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "3" {
            Ok(Self)
        } else {
            Err(VersionErr)
        }
    }
}
