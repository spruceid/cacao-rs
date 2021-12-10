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

impl From<SVersion> for Version {
    fn from(v: SVersion) -> Self {
        match v {
            SVersion::V1 => Self::V1,
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

impl From<Message> for Payload {
    fn from(m: Message) -> Self {
        Self {
            domain: m.domain,
            iss: format!(
                "did:pkh:eip155:{}:0x{}",
                m.chain_id,
                hex::encode(&m.address)
            )
            .parse()
            .unwrap(),
            statement: m.statement,
            aud: m.uri,
            version: m.version.into(),
            nonce: m.nonce,
            iat: m.issued_at,
            nbf: m.not_before,
            exp: m.expiration_time,
            request_id: m.request_id,
            resources: m.resources,
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BasicSignature;
    use hex::FromHex;
    use siwe::eip4361::Message;
    use std::str::FromStr;

    #[async_std::test]
    async fn validation() {
        // from https://github.com/blockdemy/eth_personal_sign
        let message: Payload = Message::from_str(
            r#"localhost:4361 wants you to sign in with your Ethereum account:
0x6Da01670d8fc844e736095918bbE11fE8D564163

SIWE Notepad Example

URI: http://localhost:4361
Version: 1
Chain ID: 1
Nonce: kEWepMt9knR6lWJ6A
Issued At: 2021-12-07T18:28:18.807Z"#,
        )
        .unwrap()
        .into();
        let correct = <[u8; 65]>::from_hex(r#"6228b3ecd7bf2df018183aeab6b6f1db1e9f4e3cbe24560404112e25363540eb679934908143224d746bbb5e1aa65ab435684081f4dbb74a0fec57f98f40f5051c"#).unwrap();
        SignInWithEthereum::verify(&message, &BasicSignature { s: correct })
            .await
            .unwrap();

        let incorrect = <[u8; 65]>::from_hex(r#"7228b3ecd7bf2df018183aeab6b6f1db1e9f4e3cbe24560404112e25363540eb679934908143224d746bbb5e1aa65ab435684081f4dbb74a0fec57f98f40f5051c"#).unwrap();
        assert!(
            SignInWithEthereum::verify(&message, &BasicSignature { s: incorrect })
                .await
                .is_err()
        );
    }
}
