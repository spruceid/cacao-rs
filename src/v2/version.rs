use serde_with::{DeserializeFromStr, SerializeDisplay};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, SerializeDisplay, DeserializeFromStr)]
pub struct Version2;

impl std::fmt::Display for Version2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "2")
    }
}

#[derive(Error, Debug, Copy, PartialEq)]
pub struct VersionErr;

impl std::str::FromStr for Version2 {
    type Err = VersionErr;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "2" {
            Ok(Self)
        } else {
            Err(VersionErr)
        }
    }
}
