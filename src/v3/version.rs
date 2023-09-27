use serde::{de::Deserializer, ser::Serializer, Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug, Default)]
pub struct Version3;

impl Serialize for Version3 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str("3")
    }
}

impl<'de> Deserialize<'de> for Version3 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        if s == "3" {
            Ok(Self::V1)
        } else {
            Err(serde::de::Error::custom("invalid version"))
        }
    }
}
