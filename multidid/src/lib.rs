use iri_string::types::{UriFragmentString, UriQueryString, UriReferenceString, UriRelativeString};
use std::io::{Error as IoError, Read, Write};
use unsigned_varint::{
    encode::{u64 as write_u64, u64_buffer},
    io::read_u64,
};

mod error;
mod key;
mod method;
mod pkh;

pub use error::Error;
pub use key::DidKeyTypes;
pub use method::Method;
pub use pkh::DidPkhTypes;

const MULTIDID_VARINT_TAG: u16 = 0x9d1a;

#[derive(Debug, Clone, PartialEq)]
pub struct MultiDid {
    method: Method,
    fragment: Option<UriFragmentString>,
    query: Option<UriQueryString>,
}

impl std::fmt::Display for MultiDid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.method)?;
        if let Some(fragment) = &self.fragment {
            write!(f, "#{}", fragment)?;
        }
        if let Some(query) = &self.query {
            write!(f, "?{}", query)?;
        }
        Ok(())
    }
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

    pub fn to_vec(&self) -> Vec<u8> {
        match (&self.query, &self.fragment) {
            (Some(q), Some(f)) => [
                self.method.to_vec(),
                q.as_str().as_bytes().to_vec(),
                f.as_str().as_bytes().to_vec(),
            ]
            .concat(),
            (None, Some(f)) => [self.method.to_vec(), f.as_str().as_bytes().to_vec()].concat(),
            (Some(q), None) => [self.method.to_vec(), q.as_str().as_bytes().to_vec()].concat(),
            (None, None) => self.method.to_vec(),
        }
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
                    Method::Raw(match r.scheme_str() {
                        Some(s) => format!("{}:{}", s, r.path_str()),
                        None => r.path_str().to_string(),
                    }),
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

    pub fn to_writer<W: Write>(&self, writer: &mut W) -> Result<(), IoError> {
        writer.write_all(&MULTIDID_VARINT_TAG.to_be_bytes())?;
        // write codec
        let mut buf = u64_buffer();
        writer.write_all(write_u64(self.method.codec(), &mut buf))?;

        match self.method {
            Method::Pkh(_) | Method::Key(_) => {
                self.method.to_writer(writer)?;
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
            Method::Raw(ref raw) => {
                let len: u64 = (self
                    .fragment
                    .as_ref()
                    .map(|f| f.as_str().len() + 1)
                    .unwrap_or(0)
                    + self
                        .query
                        .as_ref()
                        .map(|q| q.as_str().len() + 1)
                        .unwrap_or(0)
                    + raw.len()) as u64;
                writer.write_all(write_u64(len, &mut buf))?;
                writer.write_all(raw.as_bytes())?;
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use serde_with::{hex::Hex, serde_as};

    #[serde_as]
    #[derive(Deserialize)]
    struct ValidTest {
        #[serde_as(as = "Hex")]
        encoded: Vec<u8>,
        decoded: String,
        method: String,
        query: Option<UriQueryString>,
        fragment: Option<UriFragmentString>,
    }

    const VALID_JSON: &str = include_str!("../tests/valid.json");

    #[test]
    fn it_works() {
        let valid: Vec<ValidTest> = serde_json::from_str(VALID_JSON).unwrap();
        for test in valid {
            let did = MultiDid::from_reader(&mut test.encoded.as_slice()).unwrap();
            assert_eq!(did.query, test.query);
            assert_eq!(did.fragment, test.fragment);
            assert_eq!(did.to_vec(), test.encoded);
            assert!(match (did.method(), test.method.as_str()) {
                (Method::Key(_), "key") => true,
                (Method::Pkh(_), "pkh") => true,
                (Method::Raw(_), "raw") => true,
                _ => false,
            });
        }
    }
}
