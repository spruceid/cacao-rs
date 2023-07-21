use crate::{key, pkh, pkh::PKH_CODEC, DidKeyTypes, DidPkhTypes, Error};
use std::io::{Error as IoError, Read, Write};
use std::{fmt::Display, str::FromStr};
use unsigned_varint::io::read_u64;

pub const RAW_CODEC: u64 = 0x55;

#[derive(Debug, Clone, PartialEq)]
pub enum Method {
    Pkh(DidPkhTypes),
    Key(DidKeyTypes),
    Raw(String),
}

impl Method {
    pub fn codec(&self) -> u64 {
        use Method::*;
        match self {
            Raw(_) => RAW_CODEC,
            Pkh(h) => h.codec(),
            Key(k) => k.codec(),
        }
    }

    pub(crate) fn to_vec(&self) -> Vec<u8> {
        match self {
            Self::Raw(raw) => raw.as_bytes().to_vec(),
            Self::Pkh(h) => h.to_vec(),
            Self::Key(k) => k.to_vec(),
        }
    }

    pub(crate) fn from_reader<R: Read>(reader: &mut R) -> Result<Self, Error> {
        let codec = read_u64(reader.by_ref())?;
        match codec {
            RAW_CODEC => {
                let len = read_u64(reader.by_ref())?;
                let mut buf = vec![0; len as usize];
                reader.read_exact(&mut buf)?;
                Ok(Self::Raw(String::from_utf8(buf)?))
            }
            PKH_CODEC => Ok(Self::Pkh(DidPkhTypes::from_reader(reader)?)),
            codec => {
                let key = DidKeyTypes::from_reader(reader, codec)?;
                Ok(Self::Key(key))
            }
        }
    }

    pub(crate) fn to_writer<W: Write>(&self, writer: &mut W) -> Result<(), IoError> {
        match self {
            Self::Raw(buf) => {
                writer.write_all(buf.as_bytes())?;
            }
            Self::Pkh(pkh) => {
                pkh.to_writer(writer)?;
            }
            Self::Key(key) => {
                key.to_writer(writer)?;
            }
        }
        Ok(())
    }
}

impl Display for Method {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Method::Raw(raw) => write!(f, "{}", raw),
            Method::Pkh(pkh) => write!(f, "pkh:{}", pkh),
            Method::Key(key) => write!(f, "key:{}", key),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ParseErr {
    #[error(transparent)]
    Pkh(#[from] pkh::ParseErr),
    #[error(transparent)]
    Key(#[from] key::ParseErr),
    #[error("Invalid DID")]
    Invalid,
}

impl FromStr for Method {
    type Err = ParseErr;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match (s.get(..4), s.get(4..)) {
            (Some("pkh:"), Some(rest)) => Ok(Self::Pkh(rest.parse()?)),
            (Some("key:"), Some(rest)) => Ok(Self::Key(rest.parse()?)),
            // TODO enforce did encoding
            _ => Ok(Self::Raw(s.to_string())),
        }
    }
}
