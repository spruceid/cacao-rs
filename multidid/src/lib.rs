use iri_string::types::{UriFragmentString, UriQueryString, UriReferenceString, UriRelativeString};
use serde::{Deserialize, Serialize};
use std::io::{Error as IoError, Read, Write};
use unsigned_varint::{
    encode::{u64 as write_u64, u64_buffer},
    io::read_u64,
};

const RAW_CODEC: u64 = 0x55;
const PKH_CODEC: u64 = 0xca;
const SECP256K1_CODEC: u64 = 0xe7;
const BLS12_381_G1_CODEC: u64 = 0xea;
const BLS12_381_G2_CODEC: u64 = 0xeb;
const X25519_CODEC: u64 = 0xec;
const ED25519_CODEC: u64 = 0xed;
const P256_CODEC: u64 = 0x1200;
const P384_CODEC: u64 = 0x1201;
const P521_CODEC: u64 = 0x1202;
// const RSA_CODEC: u64 = 0x1205;

const MULTIDID_VARINT_TAG: u16 = 0x9d1a;

#[derive(Debug, Clone, PartialEq)]
pub struct MultiDid {
    method: Method,
    fragment: Option<UriFragmentString>,
    query: Option<UriQueryString>,
}

impl MultiDid {
    pub fn new(
        method: Method,
        fragment: Option<UriFragmentString>,
        query: Option<UriQueryString>,
    ) -> Self {
        Self {
            method,
            fragment,
            query,
        }
    }

    pub fn method(&self) -> &Method {
        &self.method
    }

    pub fn fragment(&self) -> Option<&UriFragmentString> {
        self.fragment.as_ref()
    }

    pub fn query(&self) -> Option<&UriQueryString> {
        self.query.as_ref()
    }

    pub fn to_vec(&self) -> Result<Vec<u8>, Error> {
        let mut buf = Vec::new();
        self.to_writer(&mut buf)?;
        Ok(buf)
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        Self::from_reader(&mut b.as_ref())
    }

    pub fn from_reader<R: Read>(reader: &mut R) -> Result<Self, Error> {
        let mut tag = [0u8; 2];
        reader.read_exact(&mut tag)?;
        let tag = u16::from_be_bytes(tag);

        if tag != MULTIDID_VARINT_TAG {
            return Err(Error::InvalidPrefix(tag as u64));
        }

        let method = Method::from_reader(reader)?;

        Ok(match method {
            Method::Raw(raw) => {
                let r = UriReferenceString::try_from(raw.as_bytes())?;
                Self::new(
                    Method::Raw(r.path_str().to_string()),
                    r.fragment().map(|f| f.to_owned()),
                    r.query().map(|q| q.to_owned()),
                )
            }
            Method::Pkh(_) | Method::Key(_) => {
                let param_len = read_u64(reader.by_ref())?;

                let (fragment, query) = if param_len > 0 {
                    let mut param_buf = vec![0; param_len as usize];
                    reader.read_exact(&mut param_buf)?;
                    let r = UriRelativeString::try_from(param_buf.as_slice())?;
                    (
                        r.fragment().map(|f| f.to_owned()),
                        r.query().map(|q| q.to_owned()),
                    )
                } else {
                    (None, None)
                };
                Self::new(method, fragment, query)
            }
        })
    }

    pub fn to_writer<W: Write>(&self, writer: &mut W) -> Result<(), Error> {
        self.method.to_writer(writer)?;
        match self.method {
            Method::Pkh(_) | Method::Key(_) => {
                let mut buf = u64_buffer();
                let len: u64 = (self
                    .fragment
                    .as_ref()
                    .map(|f| f.as_str().len() + 1)
                    .unwrap_or(0)
                    + self
                        .query
                        .as_ref()
                        .map(|q| q.as_str().len() + 1)
                        .unwrap_or(0)) as u64;
                writer.write_all(write_u64(len, &mut buf))?;
            }
            _ => {}
        };
        match (&self.fragment, &self.query) {
            (Some(fragment), Some(query)) => {
                writer.write_all(b"#")?;
                writer.write_all(fragment.as_str().as_bytes())?;
                writer.write_all(b"?")?;
                writer.write_all(query.as_str().as_bytes())?;
            }
            (Some(fragment), None) => {
                writer.write_all(b"#")?;
                writer.write_all(fragment.as_str().as_bytes())?;
            }
            (None, Some(query)) => {
                writer.write_all(b"?")?;
                writer.write_all(query.as_str().as_bytes())?;
            }
            (None, None) => {}
        };
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Method {
    Pkh(Vec<u8>),
    Key(DidKeyTypes),
    Raw(String),
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Varint(#[from] unsigned_varint::io::ReadError),
    #[error(transparent)]
    Io(#[from] IoError),
    #[error("Invalid multidid varint prefix, expected 0x9d1a, recieved {0:x}")]
    InvalidPrefix(u64),
    #[error(transparent)]
    Parameter(#[from] iri_string::validate::Error),
    #[error(transparent)]
    DidParse(#[from] std::string::FromUtf8Error),
}

impl Method {
    pub fn codec(&self) -> u64 {
        use Method::*;
        match self {
            Raw(_) => RAW_CODEC,
            Pkh(_) => PKH_CODEC,
            Key(k) => k.codec(),
        }
    }

    fn from_reader<R: Read>(reader: &mut R) -> Result<Self, Error> {
        let codec = read_u64(reader.by_ref())?;
        match codec {
            RAW_CODEC => {
                let len = read_u64(reader.by_ref())?;
                let mut buf = vec![0; len as usize];
                reader.read_exact(&mut buf)?;
                Ok(Self::Raw(String::from_utf8(buf)?))
            }
            PKH_CODEC => {
                let len = read_u64(reader.by_ref())?;
                let mut buf = vec![0; len as usize];
                reader.read_exact(&mut buf)?;
                Ok(Self::Pkh(buf))
            }
            _ => {
                let key = DidKeyTypes::from_reader(reader)?;
                Ok(Self::Key(key))
            }
        }
    }

    fn to_writer<W: Write>(&self, writer: &mut W) -> Result<(), IoError> {
        let mut vi_buf = u64_buffer();
        writer.write(write_u64(self.codec(), &mut vi_buf))?;
        match self {
            Self::Raw(buf) => {
                writer.write_all(write_u64(buf.as_bytes().len() as u64, &mut vi_buf))?;
                writer.write_all(buf.as_bytes())?;
            }
            Self::Pkh(buf) => {
                writer.write_all(write_u64(buf.len() as u64, &mut vi_buf))?;
                writer.write_all(buf)?;
            }
            Self::Key(key) => {
                key.to_writer(writer)?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum DidKeyTypes {
    Secp256k1([u8; 33]),
    Bls12_381G1([u8; 64]),
    Bls12_381G2([u8; 96]),
    X25519([u8; 32]),
    Ed25519([u8; 32]),
    P256([u8; 33]),
    P384([u8; 49]),
    P521([u8; 67]),
    // RSA([u8; ??]),
}

impl DidKeyTypes {
    pub fn codec(&self) -> u64 {
        use DidKeyTypes::*;
        match self {
            Secp256k1(_) => SECP256K1_CODEC,
            Bls12_381G1(_) => BLS12_381_G1_CODEC,
            Bls12_381G2(_) => BLS12_381_G2_CODEC,
            X25519(_) => X25519_CODEC,
            Ed25519(_) => ED25519_CODEC,
            P256(_) => P256_CODEC,
            P384(_) => P384_CODEC,
            P521(_) => P521_CODEC,
        }
    }

    fn from_reader<R>(reader: &mut R) -> Result<Self, Error>
    where
        R: Read,
    {
        let codec = read_u64(reader.by_ref())?;
        match codec {
            SECP256K1_CODEC => {
                let mut buf = [0; 33];
                reader.read_exact(&mut buf)?;
                Ok(Self::Secp256k1(buf))
            }
            BLS12_381_G1_CODEC => {
                let mut buf = [0; 64];
                reader.read_exact(&mut buf)?;
                Ok(Self::Bls12_381G1(buf))
            }
            BLS12_381_G2_CODEC => {
                let mut buf = [0; 96];
                reader.read_exact(&mut buf)?;
                Ok(Self::Bls12_381G2(buf))
            }
            X25519_CODEC => {
                let mut buf = [0; 32];
                reader.read_exact(&mut buf)?;
                Ok(Self::X25519(buf))
            }
            ED25519_CODEC => {
                let mut buf = [0; 32];
                reader.read_exact(&mut buf)?;
                Ok(Self::Ed25519(buf))
            }
            P256_CODEC => {
                let mut buf = [0; 33];
                reader.read_exact(&mut buf)?;
                Ok(Self::P256(buf))
            }
            P384_CODEC => {
                let mut buf = [0; 49];
                reader.read_exact(&mut buf)?;
                Ok(Self::P384(buf))
            }
            P521_CODEC => {
                let mut buf = [0; 67];
                reader.read_exact(&mut buf)?;
                Ok(Self::P521(buf))
            }
            _ => Err(Error::InvalidPrefix(codec)),
        }
    }

    fn to_writer<W>(&self, writer: &mut W) -> Result<(), IoError>
    where
        W: ?Sized + Write,
    {
        let mut buf = u64_buffer();
        writer.write_all(write_u64(self.codec(), &mut buf))?;
        writer.write_all(&self.bytes())
    }

    fn bytes(&self) -> &[u8] {
        match self {
            Self::Secp256k1(key) => key,
            Self::Bls12_381G1(key) => key,
            Self::Bls12_381G2(key) => key,
            Self::X25519(key) => key,
            Self::Ed25519(key) => key,
            Self::P256(key) => key,
            Self::P384(key) => key,
            Self::P521(key) => key,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_TESTS: [(&str, &str); 1] = [(
        r"9d1a550e6578616d706c653a313233343536",
        r"did:example:123456",
    )];

    const VALID: [u8; 18] = [
        0x9d, 0x1a, 0x55, 0x0e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x3a, 0x31, 0x32, 0x33,
        0x34, 0x35, 0x36,
    ];

    #[test]
    fn it_works() {
        let did = MultiDid::from_reader(&mut &VALID[..]).unwrap();
    }
}
