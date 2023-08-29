use std::io::{Error as IoError, Read, Write};
use std::{fmt::Display, str::FromStr};
use unsigned_varint::encode::{u64 as write_u64, u64_buffer};
use unsigned_varint::io::read_u64;

const SECP256K1_CODEC: u64 = 0xe7;
const BLS12_381_G1_CODEC: u64 = 0xea;
const BLS12_381_G2_CODEC: u64 = 0xeb;
const X25519_CODEC: u64 = 0xec;
const ED25519_CODEC: u64 = 0xed;
const P256_CODEC: u64 = 0x1200;
const P384_CODEC: u64 = 0x1201;
const P521_CODEC: u64 = 0x1202;
// const RSA_CODEC: u64 = 0x1205;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Hash)]
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

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] IoError),
    #[error("Invalid key type: {0:x}")]
    InvalidCodec(u64),
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

    pub(crate) fn from_reader<R>(reader: &mut R, codec: u64) -> Result<Self, Error>
    where
        R: Read,
    {
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
            _ => Err(Error::InvalidCodec(codec)),
        }
    }

    pub(crate) fn to_writer<W>(&self, writer: &mut W) -> Result<(), IoError>
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

    pub(crate) fn to_vec(&self) -> Vec<u8> {
        let mut vec = Vec::new();
        let mut buf = u64_buffer();
        vec.extend(write_u64(self.codec(), &mut buf));
        vec.extend(self.bytes());
        vec
    }
}

impl Display for DidKeyTypes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "z{}", bs58::encode(self.to_vec()).into_string())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ParseErr {
    #[error("Invalid Base")]
    InvalidBase,
    #[error("Insufficient Length")]
    InsuficientBytes,
    #[error(transparent)]
    Varint(#[from] unsigned_varint::io::ReadError),
    #[error(transparent)]
    Base58(#[from] bs58::decode::Error),
    #[error(transparent)]
    Decoding(#[from] Error),
}

impl FromStr for DidKeyTypes {
    type Err = ParseErr;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match (s.get(..1), s.get(1..)) {
            (None, _) | (_, None) => Err(ParseErr::InsuficientBytes),
            (Some("z"), Some(rest)) => {
                let bytes = bs58::decode(rest).into_vec()?;
                let mut br = bytes.as_slice();
                let codec = read_u64(&mut br)?;
                Ok(Self::from_reader(&mut br, codec)?)
            }
            _ => Err(ParseErr::InvalidBase),
        }
    }
}
