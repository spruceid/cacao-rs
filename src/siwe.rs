use super::{BasicSignature, Payload, SignatureScheme, VerificationError, Version};
use async_trait::async_trait;
use hex::FromHex;
use siwe::eip4361::{Message, VerificationError as SVE, Version as SVersion};

impl Into<SVersion> for Version {
    fn into(self) -> SVersion {
        match self {
            Self::V1 => SVersion::V1,
        }
    }
}

impl From<SVE> for VerificationError {
    fn from(e: SVE) -> Self {
        match e {
            SVE::Crypto(_) | SVE::Signer => Self::Crypto,
            SVE::Serialization(_) => Self::Serialization,
        }
    }
}

impl TryInto<Message> for Payload {
    type Error = ();
    fn try_into(self) -> Result<Message, Self::Error> {
        let (chain_id, address) = match &self.iss.as_str().split(":").collect::<Vec<&str>>()[..] {
            &["did", "pkh", "eip155", c, h] => {
                (c.to_string(), FromHex::from_hex(&h[2..]).map_err(|_| ())?)
            }
            _ => return Err(()),
        };
        Ok(Message {
            domain: self.domain,
            address,
            chain_id,
            statement: self.statement,
            uri: self.aud,
            version: self.version.into(),
            nonce: self.nonce,
            issued_at: self.iat,
            not_before: self.nbf,
            expiration_time: self.exp,
            request_id: self.request_id,
            resources: self.resources,
        })
    }
}

pub struct SignInWithEthereum;

#[async_trait]
impl SignatureScheme for SignInWithEthereum {
    type Signature = BasicSignature<[u8; 65]>;
    fn id() -> String {
        "eip4361-eip191".into()
    }
    async fn verify(payload: &Payload, sig: &Self::Signature) -> Result<(), VerificationError> {
        if !payload.valid_now() {
            return Err(VerificationError::NotCurrentlyValid);
        };
        let m: Message = payload
            .clone()
            .try_into()
            .map_err(|_| VerificationError::MissingVerificationMaterial)?;
        m.verify_eip191(sig.s)?;
        Ok(())
    }
}
