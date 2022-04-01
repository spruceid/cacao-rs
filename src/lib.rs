use async_trait::async_trait;
use chrono::{DateTime, Utc};
use http::uri::{Authority, InvalidUri};
use iri_string::{
    types::{UriAbsoluteString, UriString},
    validate::Error as URIStringError,
};
use libipld::{
    cbor::{DagCbor, DagCborCodec},
    codec::{Decode, Encode},
    DagCbor, Ipld,
};
pub use siwe::TimeStamp;
use thiserror::Error;

pub mod generic;
pub mod siwe_cacao;

#[derive(DagCbor)]
pub struct CACAO<S>
where
    S: SignatureScheme,
    S::Signature: DagCbor,
{
    h: Header,
    p: Payload,
    s: S::Signature,
}

impl<S> CACAO<S>
where
    S: SignatureScheme,
    S::Signature: DagCbor,
{
    pub fn new(p: Payload, s: S::Signature) -> Self {
        Self {
            h: S::header(),
            p,
            s,
        }
    }

    pub fn header(&self) -> &Header {
        &self.h
    }

    pub fn payload(&self) -> &Payload {
        &self.p
    }

    pub fn signature(&self) -> &S::Signature {
        &self.s
    }

    pub async fn verify(&self) -> Result<(), VerificationError>
    where
        S: Send + Sync,
        S::Signature: Send + Sync,
    {
        S::verify_cacao(self).await
    }
}

#[derive(DagCbor, Clone, Debug, PartialEq)]
pub struct Header {
    t: String,
}

impl Header {
    pub fn t<'a>(&'a self) -> &'a str {
        &self.t.as_str()
    }
}

#[async_trait]
pub trait SignatureScheme {
    type Signature;
    fn id() -> String;
    fn header() -> Header {
        Header { t: Self::id() }
    }
    async fn verify(payload: &Payload, sig: &Self::Signature) -> Result<(), VerificationError>
    where
        Self::Signature: Send + Sync;

    async fn verify_cacao(cacao: &CACAO<Self>) -> Result<(), VerificationError>
    where
        Self: Sized,
        Self::Signature: Send + Sync + DagCbor,
    {
        Self::verify(cacao.payload(), cacao.signature()).await
    }
}

#[derive(Error, Debug)]
pub enum VerificationError {
    #[error("Verification Failed")]
    Crypto,
    #[error("Normalisation of verification input failed")]
    Serialization,
    #[error("Missing Payload Verification Material")]
    MissingVerificationMaterial,
    #[error("Not Currently Valid")]
    NotCurrentlyValid,
}

#[derive(DagCbor)]
pub struct BasicSignature<S>
where
    S: DagCbor + AsRef<[u8]> + TryFrom<Vec<u8>>,
{
    pub s: S,
}

impl<S> AsRef<[u8]> for BasicSignature<S>
where
    S: DagCbor + AsRef<[u8]> + TryFrom<Vec<u8>>,
{
    fn as_ref(&self) -> &[u8] {
        self.s.as_ref()
    }
}

impl<S> TryFrom<Vec<u8>> for BasicSignature<S>
where
    S: DagCbor + AsRef<[u8]> + TryFrom<Vec<u8>>,
{
    type Error = <S as TryFrom<Vec<u8>>>::Error;
    fn try_from(s: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(Self { s: s.try_into()? })
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Version {
    V1 = 1,
}

#[derive(Clone, PartialEq, Debug)]
pub struct Payload {
    pub domain: Authority,
    pub iss: UriAbsoluteString,
    pub statement: Option<String>,
    pub aud: UriString,
    pub version: Version,
    pub nonce: String,
    pub iat: TimeStamp,
    pub exp: Option<TimeStamp>,
    pub nbf: Option<TimeStamp>,
    pub request_id: Option<String>,
    pub resources: Vec<UriString>,
}
impl Payload {
    pub fn sign<S: SignatureScheme>(self, s: S::Signature) -> CACAO<S>
    where
        S::Signature: DagCbor,
    {
        CACAO {
            h: S::header(),
            p: self,
            s,
        }
    }

    pub async fn verify<S: SignatureScheme>(
        &self,
        s: &<S as SignatureScheme>::Signature,
    ) -> Result<(), VerificationError>
    where
        S: Send + Sync,
        S::Signature: Send + Sync,
    {
        S::verify(self, s).await
    }

    pub fn iss(&self) -> &str {
        self.iss.as_str()
    }

    pub fn valid_at(&self, t: &DateTime<Utc>) -> bool {
        self.nbf.as_ref().map(|nbf| nbf < t).unwrap_or(true)
            && self.exp.as_ref().map(|exp| exp >= t).unwrap_or(true)
    }

    pub fn valid_now(&self) -> bool {
        self.valid_at(&Utc::now())
    }
}

mod payload_ipld {
    use super::*;
    use libipld::error::Error as IpldError;
    use std::io::{Read, Seek, Write};

    #[derive(Clone, DagCbor)]
    struct TmpPayload {
        domain: String,
        iss: String,
        #[ipld(default = None)]
        statement: Option<String>,
        aud: String,
        version: String,
        nonce: String,
        iat: String,
        #[ipld(default = None)]
        exp: Option<String>,
        #[ipld(default = None)]
        nbf: Option<String>,
        #[ipld(rename = "requestId")]
        #[ipld(default = None)]
        request_id: Option<String>,
        resources: Vec<String>,
    }

    impl From<&Payload> for TmpPayload {
        fn from(p: &Payload) -> Self {
            Self {
                domain: p.domain.to_string(),
                iss: p.iss.to_string(),
                statement: p.statement.as_ref().map(|e| e.to_string()),
                aud: p.aud.to_string(),
                version: (p.version as u64).to_string(),
                nonce: p.nonce.to_string(),
                iat: p.iat.to_string(),
                exp: p.exp.as_ref().map(|e| e.to_string()),
                nbf: p.nbf.as_ref().map(|e| e.to_string()),
                request_id: p.request_id.clone(),
                resources: p.resources.iter().map(|r| r.to_string()).collect(),
            }
        }
    }

    #[derive(Error, Debug)]
    pub enum PayloadIpldParseError {
        #[error(transparent)]
        Domain(#[from] InvalidUri),
        #[error(transparent)]
        Uri(#[from] URIStringError),
        #[error(transparent)]
        TimeStamp(#[from] chrono::format::ParseError),
    }

    impl TryFrom<TmpPayload> for Payload {
        type Error = PayloadIpldParseError;
        fn try_from(p: TmpPayload) -> Result<Self, Self::Error> {
            Ok(Self {
                domain: p.domain.parse()?,
                iss: p.iss.parse()?,
                statement: p.statement,
                aud: p.aud.parse()?,
                version: Version::V1,
                nonce: p.nonce,
                iat: p.iat.parse()?,
                exp: p.exp.map(|s| s.parse()).transpose()?,
                nbf: p.nbf.map(|s| s.parse()).transpose()?,
                request_id: p.request_id,
                resources: p
                    .resources
                    .iter()
                    .map(|r| r.parse())
                    .collect::<Result<Vec<UriString>, URIStringError>>()?,
            })
        }
    }

    impl Encode<DagCborCodec> for Payload {
        fn encode<W>(&self, c: DagCborCodec, w: &mut W) -> Result<(), IpldError>
        where
            W: Write,
        {
            TmpPayload::from(self).encode(c, w)
        }
    }

    impl Decode<DagCborCodec> for Payload {
        fn decode<R>(c: DagCborCodec, r: &mut R) -> Result<Self, IpldError>
        where
            R: Read + Seek,
        {
            TmpPayload::decode(c, r).and_then(|t| Ok(t.try_into()?))
        }
    }
}

#[derive(DagCbor, Debug, PartialEq)]
pub struct CACAOIpld {
    #[ipld(rename = "h")]
    header: Header,
    #[ipld(rename = "p")]
    payload: Payload,
    #[ipld(rename = "s")]
    signature: Ipld,
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use libipld::codec::assert_roundtrip;
    use libipld::ipld;
    use std::io::Cursor;
    #[test]
    fn test_ipld() {
        let cacao = CACAOIpld::decode(
            DagCborCodec,
            &mut Cursor::new([
                163u8, 97u8, 104u8, 161u8, 97u8, 116u8, 103u8, 101u8, 105u8, 112u8, 52u8, 51u8,
                54u8, 49u8, 97u8, 112u8, 168u8, 99u8, 97u8, 117u8, 100u8, 120u8, 56u8, 100u8,
                105u8, 100u8, 58u8, 107u8, 101u8, 121u8, 58u8, 122u8, 54u8, 77u8, 107u8, 114u8,
                66u8, 100u8, 78u8, 100u8, 119u8, 85u8, 80u8, 110u8, 88u8, 68u8, 86u8, 68u8, 49u8,
                68u8, 67u8, 120u8, 101u8, 100u8, 122u8, 86u8, 86u8, 66u8, 112u8, 97u8, 71u8, 105u8,
                56u8, 97u8, 83u8, 109u8, 111u8, 88u8, 70u8, 65u8, 101u8, 75u8, 78u8, 103u8, 116u8,
                65u8, 101u8, 114u8, 56u8, 99u8, 105u8, 97u8, 116u8, 120u8, 24u8, 50u8, 48u8, 50u8,
                49u8, 45u8, 48u8, 57u8, 45u8, 51u8, 48u8, 84u8, 49u8, 54u8, 58u8, 50u8, 53u8, 58u8,
                50u8, 52u8, 46u8, 48u8, 48u8, 48u8, 90u8, 99u8, 105u8, 115u8, 115u8, 120u8, 59u8,
                100u8, 105u8, 100u8, 58u8, 112u8, 107u8, 104u8, 58u8, 101u8, 105u8, 112u8, 49u8,
                53u8, 53u8, 58u8, 49u8, 58u8, 48u8, 120u8, 66u8, 100u8, 57u8, 68u8, 57u8, 99u8,
                55u8, 68u8, 67u8, 51u8, 56u8, 57u8, 55u8, 49u8, 53u8, 97u8, 56u8, 57u8, 102u8,
                67u8, 56u8, 49u8, 52u8, 57u8, 69u8, 52u8, 97u8, 53u8, 66u8, 101u8, 57u8, 49u8,
                51u8, 51u8, 54u8, 66u8, 50u8, 55u8, 57u8, 54u8, 101u8, 110u8, 111u8, 110u8, 99u8,
                101u8, 104u8, 51u8, 50u8, 56u8, 57u8, 49u8, 55u8, 53u8, 55u8, 102u8, 100u8, 111u8,
                109u8, 97u8, 105u8, 110u8, 107u8, 115u8, 101u8, 114u8, 118u8, 105u8, 99u8, 101u8,
                46u8, 111u8, 114u8, 103u8, 103u8, 118u8, 101u8, 114u8, 115u8, 105u8, 111u8, 110u8,
                97u8, 49u8, 105u8, 114u8, 101u8, 115u8, 111u8, 117u8, 114u8, 99u8, 101u8, 115u8,
                130u8, 120u8, 53u8, 105u8, 112u8, 102u8, 115u8, 58u8, 47u8, 47u8, 81u8, 109u8,
                101u8, 55u8, 115u8, 115u8, 51u8, 65u8, 82u8, 86u8, 103u8, 120u8, 118u8, 54u8,
                114u8, 88u8, 113u8, 86u8, 80u8, 105u8, 105u8, 107u8, 77u8, 74u8, 56u8, 117u8, 50u8,
                78u8, 76u8, 103u8, 109u8, 103u8, 115u8, 122u8, 103u8, 49u8, 51u8, 112u8, 89u8,
                114u8, 68u8, 75u8, 69u8, 111u8, 105u8, 117u8, 120u8, 38u8, 104u8, 116u8, 116u8,
                112u8, 115u8, 58u8, 47u8, 47u8, 101u8, 120u8, 97u8, 109u8, 112u8, 108u8, 101u8,
                46u8, 99u8, 111u8, 109u8, 47u8, 109u8, 121u8, 45u8, 119u8, 101u8, 98u8, 50u8, 45u8,
                99u8, 108u8, 97u8, 105u8, 109u8, 46u8, 106u8, 115u8, 111u8, 110u8, 105u8, 115u8,
                116u8, 97u8, 116u8, 101u8, 109u8, 101u8, 110u8, 116u8, 120u8, 65u8, 73u8, 32u8,
                97u8, 99u8, 99u8, 101u8, 112u8, 116u8, 32u8, 116u8, 104u8, 101u8, 32u8, 83u8,
                101u8, 114u8, 118u8, 105u8, 99u8, 101u8, 79u8, 114u8, 103u8, 32u8, 84u8, 101u8,
                114u8, 109u8, 115u8, 32u8, 111u8, 102u8, 32u8, 83u8, 101u8, 114u8, 118u8, 105u8,
                99u8, 101u8, 58u8, 32u8, 104u8, 116u8, 116u8, 112u8, 115u8, 58u8, 47u8, 47u8,
                115u8, 101u8, 114u8, 118u8, 105u8, 99u8, 101u8, 46u8, 111u8, 114u8, 103u8, 47u8,
                116u8, 111u8, 115u8, 97u8, 115u8, 162u8, 97u8, 115u8, 120u8, 132u8, 48u8, 120u8,
                49u8, 48u8, 57u8, 51u8, 49u8, 51u8, 101u8, 55u8, 53u8, 50u8, 53u8, 100u8, 101u8,
                97u8, 53u8, 53u8, 101u8, 99u8, 57u8, 97u8, 51u8, 99u8, 99u8, 98u8, 98u8, 54u8,
                51u8, 101u8, 97u8, 56u8, 100u8, 54u8, 56u8, 52u8, 48u8, 54u8, 51u8, 54u8, 54u8,
                50u8, 53u8, 48u8, 99u8, 102u8, 48u8, 56u8, 56u8, 48u8, 100u8, 54u8, 55u8, 48u8,
                51u8, 50u8, 98u8, 52u8, 53u8, 55u8, 97u8, 98u8, 51u8, 51u8, 99u8, 57u8, 50u8, 54u8,
                99u8, 54u8, 55u8, 102u8, 102u8, 51u8, 102u8, 99u8, 99u8, 54u8, 54u8, 97u8, 99u8,
                51u8, 49u8, 98u8, 97u8, 97u8, 54u8, 56u8, 54u8, 56u8, 97u8, 56u8, 48u8, 97u8, 49u8,
                50u8, 102u8, 98u8, 101u8, 54u8, 98u8, 55u8, 54u8, 51u8, 56u8, 97u8, 56u8, 57u8,
                102u8, 52u8, 102u8, 54u8, 100u8, 53u8, 49u8, 97u8, 48u8, 50u8, 50u8, 57u8, 53u8,
                57u8, 48u8, 99u8, 102u8, 54u8, 54u8, 55u8, 54u8, 102u8, 49u8, 99u8, 97u8, 116u8,
                102u8, 101u8, 105u8, 112u8, 49u8, 57u8, 49u8,
            ]),
        )
        .unwrap();
        assert_roundtrip(
            DagCborCodec,
            &cacao,
            &ipld!({
              "h": {
                "t": "eip4361",
              },
              "p": {
                "aud": "did:key:z6MkrBdNdwUPnXDVD1DCxedzVVBpaGi8aSmoXFAeKNgtAer8",
                "domain": "service.org",
                "iat": "2021-09-30T16:25:24.000Z",
                "iss": "did:pkh:eip155:1:0xBd9D9c7DC389715a89fC8149E4a5Be91336B2796",
                "nonce": "32891757",
                "resources": [
                  "ipfs://Qme7ss3ARVgxv6rXqVPiikMJ8u2NLgmgszg13pYrDKEoiu",
                  "https://example.com/my-web2-claim.json",
                ],
                "statement": "I accept the ServiceOrg Terms of Service: https://service.org/tos",
                "version": "1",
              },
              "s": {
                "s": "0x109313e7525dea55ec9a3ccbb63ea8d68406366250cf0880d67032b457ab33c926c67ff3fcc66ac31baa6868a80a12fbe6b7638a89f4f6d51a0229590cf6676f1c",
                "t": "eip191",
              },
            }),
        );
    }
}
