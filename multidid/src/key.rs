use crate::Error;
use std::io::{Error as IoError, Read, Write};

const SECP256K1_CODEC: u64 = 0xe7;
const BLS12_381_G1_CODEC: u64 = 0xea;
const BLS12_381_G2_CODEC: u64 = 0xeb;
const X25519_CODEC: u64 = 0xec;
const ED25519_CODEC: u64 = 0xed;
const P256_CODEC: u64 = 0x1200;
const P384_CODEC: u64 = 0x1201;
const P521_CODEC: u64 = 0x1202;
// const RSA_CODEC: u64 = 0x1205;

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
            _ => Err(Error::InvalidPrefix(codec)),
        }
    }

    pub(crate) fn to_writer<W>(&self, writer: &mut W) -> Result<(), IoError>
    where
        W: ?Sized + Write,
    {
        writer.write_all(&self.bytes())
    }

    pub fn bytes(&self) -> &[u8] {
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
