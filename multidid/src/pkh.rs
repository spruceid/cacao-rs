use bech32::{FromBase32, ToBase32};
use sha3::{Digest, Keccak256};
use std::io::{Error as IoError, Read, Write};
use std::{
    fmt::{Display, Formatter, Result as FmtResult},
    str::FromStr,
};
use unsigned_varint::{
    encode::{u64 as write_u64, u64_buffer},
    io::read_u64,
};

pub(crate) const PKH_CODEC: u64 = 0xca;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DidPkhTypes {
    Bip122(Caip10<[u8; 32], [u8; 25]>),
    Eip155(Caip10<u64, [u8; 20]>),
    Cosmos(Caip10<String, CosmosAddress>),
    Starknet(Caip10<String, [u8; 32]>),
    Hedera(Caip10<String, HederaAddress>),
    Lip9(Caip10<[u8; 32], [u8; 20]>),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Caip10<C, A> {
    chain_id: C,
    address: A,
}

impl<C, A> Caip10<C, A> {
    pub fn new(chain_id: C, address: A) -> Self {
        Self { chain_id, address }
    }
    pub fn chain_id(&self) -> &C {
        &self.chain_id
    }
    pub fn address(&self) -> &A {
        &self.address
    }
    pub fn into_inner(self) -> (C, A) {
        (self.chain_id, self.address)
    }
}

impl<C, A> From<(C, A)> for Caip10<C, A> {
    fn from((chain_id, address): (C, A)) -> Self {
        Self::new(chain_id, address)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CosmosAddress {
    Secp256k1([u8; 20]),
    Secp256r1([u8; 32]),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HederaAddress {
    EVM([u8; 20]),
    Ed25519([u8; 32]),
    Secp256k1([u8; 33]),
}

impl CosmosAddress {
    pub fn bytes(&self) -> &[u8] {
        match self {
            CosmosAddress::Secp256k1(address) => address,
            CosmosAddress::Secp256r1(address) => address,
        }
    }
}

impl HederaAddress {
    pub fn bytes(&self) -> &[u8] {
        match self {
            HederaAddress::EVM(address) => address,
            HederaAddress::Ed25519(address) => address,
            HederaAddress::Secp256k1(address) => address,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] IoError),
    #[error("Invalid PKH discriminant: {0}")]
    InvalidPkh(u64),
    #[error(transparent)]
    Utf8(#[from] std::string::FromUtf8Error),
    #[error(transparent)]
    Varint(#[from] unsigned_varint::io::ReadError),
    #[error("Invalid Hedera length: {0}")]
    InvalidHederaLength(u64),
    #[error("Invalid Cosmos length: {0}")]
    InvalidCosmosLength(u64),
}

impl DidPkhTypes {
    pub fn caip_2_code(&self) -> &'static str {
        use DidPkhTypes::*;
        match self {
            Bip122(_) => "bip122",
            Eip155(_) => "eip155",
            Cosmos(_) => "cosmos",
            Starknet(_) => "starknet",
            Hedera(_) => "hedera",
            Lip9(_) => "lip9",
        }
    }

    pub fn codec(&self) -> u64 {
        PKH_CODEC
    }

    pub(crate) fn to_vec(&self) -> Vec<u8> {
        let mut vec = Vec::new();
        vec.push(PKH_CODEC as u8);
        let mut buf = u64_buffer();
        match self {
            DidPkhTypes::Bip122(caip10) => {
                vec.extend(write_u64(1, &mut buf));
                vec.extend(caip10.chain_id());
                vec.extend(caip10.address());
            }
            DidPkhTypes::Eip155(caip10) => {
                vec.extend(write_u64(2, &mut buf));
                vec.extend(write_u64(*caip10.chain_id(), &mut buf));
                vec.extend(caip10.address());
            }
            DidPkhTypes::Cosmos(caip10) => {
                vec.extend(write_u64(3, &mut buf));
                vec.extend(write_u64(caip10.chain_id().len() as u64, &mut buf));
                vec.extend(caip10.chain_id().as_bytes());
                match caip10.address() {
                    CosmosAddress::Secp256k1(address) => {
                        vec.extend(write_u64(20, &mut buf));
                        vec.extend(address);
                    }
                    CosmosAddress::Secp256r1(address) => {
                        vec.extend(write_u64(32, &mut buf));
                        vec.extend(address);
                    }
                }
            }
            DidPkhTypes::Starknet(caip10) => {
                vec.extend(write_u64(3, &mut buf));
                vec.extend(write_u64(caip10.chain_id().len() as u64, &mut buf));
                vec.extend(caip10.chain_id().as_bytes());
                vec.extend(caip10.address());
            }
            DidPkhTypes::Hedera(caip10) => {
                vec.extend(write_u64(3, &mut buf));
                vec.extend(write_u64(caip10.chain_id().len() as u64, &mut buf));
                vec.extend(caip10.chain_id().as_bytes());
                match caip10.address() {
                    HederaAddress::EVM(address) => {
                        vec.extend(write_u64(20, &mut buf));
                        vec.extend(address);
                    }
                    HederaAddress::Ed25519(address) => {
                        vec.extend(write_u64(32, &mut buf));
                        vec.extend(address);
                    }
                    HederaAddress::Secp256k1(address) => {
                        vec.extend(write_u64(33, &mut buf));
                        vec.extend(address);
                    }
                }
            }
            DidPkhTypes::Lip9(caip10) => {
                vec.extend(write_u64(3, &mut buf));
                vec.extend(caip10.chain_id());
                vec.extend(caip10.address());
            }
        };
        vec
    }

    pub(crate) fn from_reader<R>(reader: &mut R) -> Result<Self, Error>
    where
        R: Read,
    {
        let pkh_type = read_u64(reader.by_ref())?;
        match pkh_type {
            // bitcoin-like
            1 => {
                let mut chain_id = [0u8; 32];
                reader.read_exact(&mut chain_id)?;
                let mut address = [0u8; 25];
                reader.read_exact(&mut address)?;
                Ok(DidPkhTypes::Bip122(Caip10::new(chain_id, address)))
            }
            // ethereum-like
            2 => {
                let chain_id = read_u64(reader.by_ref())?;
                let mut address = [0u8; 20];
                reader.read_exact(&mut address)?;
                Ok(DidPkhTypes::Eip155(Caip10::new(chain_id, address)))
            }
            // cosmos
            3 => {
                let ref_len = read_u64(reader.by_ref())?;
                let mut chain_id = vec![0u8; ref_len as usize];
                reader.read_exact(&mut chain_id)?;
                let address_len = read_u64(reader.by_ref())?;
                Ok(DidPkhTypes::Cosmos(Caip10::new(
                    String::from_utf8(chain_id)?,
                    match address_len {
                        20 => {
                            let mut address = [0u8; 20];
                            reader.read_exact(&mut address)?;
                            CosmosAddress::Secp256k1(address)
                        }
                        32 => {
                            let mut address = [0u8; 32];
                            reader.read_exact(&mut address)?;
                            CosmosAddress::Secp256r1(address)
                        }
                        l => return Err(Error::InvalidCosmosLength(l)),
                    },
                )))
            }
            // starknet
            4 => {
                let ref_len = read_u64(reader.by_ref())?;
                let mut chain_id = vec![0u8; ref_len as usize];
                reader.read_exact(&mut chain_id)?;
                let mut address = [0u8; 32];
                reader.read_exact(&mut address)?;
                Ok(DidPkhTypes::Starknet(Caip10::new(
                    String::from_utf8(chain_id)?,
                    address,
                )))
            }
            // hedera
            5 => {
                let ref_len = read_u64(reader.by_ref())?;
                let mut chain_id = vec![0u8; ref_len as usize];
                reader.read_exact(&mut chain_id)?;
                let address_len = read_u64(reader.by_ref())?;
                Ok(DidPkhTypes::Hedera(Caip10::new(
                    String::from_utf8(chain_id)?,
                    match address_len {
                        20 => {
                            let mut address = [0u8; 20];
                            reader.read_exact(&mut address)?;
                            HederaAddress::EVM(address)
                        }
                        32 => {
                            let mut address = [0u8; 32];
                            reader.read_exact(&mut address)?;
                            HederaAddress::Ed25519(address)
                        }
                        33 => {
                            let mut address = [0u8; 33];
                            reader.read_exact(&mut address)?;
                            HederaAddress::Secp256k1(address)
                        }
                        l => return Err(Error::InvalidHederaLength(l)),
                    },
                )))
            }
            // lip9
            6 => {
                let mut chain_id = [0u8; 32];
                reader.read_exact(&mut chain_id)?;
                let mut address = [0u8; 20];
                reader.read_exact(&mut address)?;
                Ok(DidPkhTypes::Lip9(Caip10::new(chain_id, address)))
            }
            t => Err(Error::InvalidPkh(t)),
        }
    }

    pub(crate) fn to_writer<W>(&self, writer: &mut W) -> Result<(), IoError>
    where
        W: ?Sized + Write,
    {
        writer.write_all(&[PKH_CODEC as u8])?;
        let mut buf = u64_buffer();
        match self {
            DidPkhTypes::Bip122(caip10) => {
                writer.write_all(write_u64(1, &mut buf))?;
                writer.write_all(caip10.chain_id())?;
                writer.write_all(caip10.address())?;
            }
            DidPkhTypes::Eip155(caip10) => {
                writer.write_all(write_u64(2, &mut buf))?;
                writer.write_all(write_u64(*caip10.chain_id() as u64, &mut buf))?;
                writer.write_all(caip10.address())?;
            }
            DidPkhTypes::Cosmos(caip10) => {
                writer.write_all(write_u64(3, &mut buf))?;
                writer.write_all(write_u64(caip10.chain_id().len() as u64, &mut buf))?;
                writer.write_all(caip10.chain_id().as_bytes())?;
                match caip10.address() {
                    CosmosAddress::Secp256k1(address) => {
                        writer.write_all(write_u64(20, &mut buf))?;
                        writer.write_all(address)?;
                    }
                    CosmosAddress::Secp256r1(address) => {
                        writer.write_all(write_u64(32, &mut buf))?;
                        writer.write_all(address)?;
                    }
                }
            }
            DidPkhTypes::Starknet(caip10) => {
                writer.write_all(write_u64(3, &mut buf))?;
                writer.write_all(write_u64(caip10.chain_id().len() as u64, &mut buf))?;
                writer.write_all(caip10.chain_id().as_bytes())?;
                writer.write_all(caip10.address())?;
            }
            DidPkhTypes::Hedera(caip10) => {
                writer.write_all(write_u64(3, &mut buf))?;
                writer.write_all(write_u64(caip10.chain_id().len() as u64, &mut buf))?;
                writer.write_all(caip10.chain_id().as_bytes())?;
                match caip10.address() {
                    HederaAddress::EVM(address) => {
                        writer.write_all(write_u64(20, &mut buf))?;
                        writer.write_all(address)?;
                    }
                    HederaAddress::Ed25519(address) => {
                        writer.write_all(write_u64(32, &mut buf))?;
                        writer.write_all(address)?;
                    }
                    HederaAddress::Secp256k1(address) => {
                        writer.write_all(write_u64(20, &mut buf))?;
                        writer.write_all(address)?;
                    }
                }
            }
            DidPkhTypes::Lip9(caip10) => {
                writer.write_all(write_u64(3, &mut buf))?;
                writer.write_all(caip10.chain_id())?;
                writer.write_all(caip10.address())?;
            }
        };
        Ok(())
    }
}

impl Display for DidPkhTypes {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::Bip122(c) => write!(
                f,
                "bip122:{}:{}",
                hex::encode(c.chain_id()),
                bs58::encode(c.address()).into_string()
            ),
            Self::Eip155(c) => write!(f, "eip155:{}:{}", c.chain_id(), eip55(c.address())),
            Self::Cosmos(c) => write!(f, "cosmos:{}:{}", c.chain_id(), c.address()),
            Self::Starknet(c) => write!(f, "starknet:{}:{}", c.chain_id(), eip55(c.address())),
            // Self::Hedera(c) => write!(f, "hedera:{}:{}", c.chain_id(), c.address()),
            // Self::Lip9(c) => write!(f, "lip9:{}:{}", c.chain_id(), c.address()),
            _ => todo!(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ParseErr {
    #[error("Invalid DID")]
    InvalidDid,
    #[error("Invalid Integer")]
    InvalidInteger(#[from] std::num::ParseIntError),
    #[error("Invalid EIP55: {0}")]
    Eip55(#[from] Eip55Err),
    #[error("Invalid Bip122")]
    Bip122,
    #[error("Invalid Cosmos Address")]
    Cosmos,
}

impl FromStr for DidPkhTypes {
    type Err = ParseErr;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(
            match s
                .split_once(":")
                .and_then(|(method, r)| Some((method, r.split_once(":")?)))
            {
                Some(("bip122", (chain_id, address))) => Self::Bip122(Caip10::new(
                    hex::decode(chain_id)
                        .map_err(|_| ParseErr::Bip122)
                        .and_then(|v| v.try_into().map_err(|_| ParseErr::Bip122))?,
                    bs58::decode(address)
                        .into_vec()
                        .map_err(|_| ParseErr::Bip122)
                        .and_then(|v| v.try_into().map_err(|_| ParseErr::Bip122))?,
                )),
                Some(("eip155", (chain_id, address))) => {
                    Self::Eip155(Caip10::new(chain_id.parse()?, parse_eip55(address)?))
                }
                Some(("cosmos", (chain_id, address))) => {
                    Self::Cosmos(Caip10::new(chain_id.to_string(), address.parse()?))
                }
                Some(("starknet", (chain_id, address))) => {
                    Self::Starknet(Caip10::new(chain_id.to_string(), parse_starknet(address)?))
                }
                Some(("hedera", (chain_id, address))) => {
                    Self::Hedera(Caip10::new(chain_id.to_string(), todo!()))
                }
                Some(("lip9", (chain_id, address))) => Self::Lip9(Caip10::new(todo!(), todo!())),
                _ => return Err(ParseErr::InvalidDid),
            },
        )
    }
}

impl Display for CosmosAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(
            f,
            "{}",
            bech32::encode("cosmos", self.bytes().to_base32(), bech32::Variant::Bech32)
                .map_err(|_| std::fmt::Error)?
        )
    }
}

impl FromStr for CosmosAddress {
    type Err = ParseErr;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        bech32::decode(s)
            .map_err(|_| ParseErr::Cosmos)
            .and_then(|(p, b32, _)| {
                if p != "cosmos" {
                    Err(ParseErr::Cosmos)
                } else {
                    match <[u8; 20]>::try_from(
                        Vec::<u8>::from_base32(&b32).map_err(|_| ParseErr::Cosmos)?,
                    ) {
                        Ok(b) => Ok(CosmosAddress::Secp256k1(b)),
                        Err(b) => Ok(CosmosAddress::Secp256r1(
                            b.try_into().map_err(|_| ParseErr::Cosmos)?,
                        )),
                    }
                }
            })
    }
}

impl Display for HederaAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            HederaAddress::EVM(address) => {
                for byte in address {
                    write!(f, "{:02x}", byte)?;
                }
            }
            HederaAddress::Ed25519(address) => {
                for byte in address {
                    write!(f, "{:02x}", byte)?;
                }
            }
            HederaAddress::Secp256k1(address) => {
                for byte in address {
                    write!(f, "{:02x}", byte)?;
                }
            }
        }
        Ok(())
    }
}

/// Takes an eth address and returns it as a checksum formatted string.
pub fn eip55<const N: usize>(addr: &[u8; N]) -> String {
    let addr_str = hex::encode(addr);
    let hash = Keccak256::digest(addr_str.as_bytes());
    "0x".chars()
        .chain(addr_str.chars().enumerate().map(|(i, c)| {
            match (c, hash[i >> 1] & if i % 2 == 0 { 128 } else { 8 } != 0) {
                ('a'..='f' | 'A'..='F', true) => c.to_ascii_uppercase(),
                _ => c.to_ascii_lowercase(),
            }
        }))
        .collect()
}

#[derive(Debug, thiserror::Error)]
pub enum Eip55Err {
    #[error("Missing Prefix 0x")]
    MissingPrefix,
    #[error("Invalid Checksum")]
    InvalidChecksum,
    #[error("Invalid hex: {0}")]
    InvalidHex(#[from] hex::FromHexError),
}

fn parse_eip55(address: &str) -> Result<[u8; 20], Eip55Err> {
    use hex::FromHex;
    if !address.starts_with("0x") {
        Err(Eip55Err::MissingPrefix)
    } else {
        let s = <[u8; 20]>::from_hex(address)?;
        let sum = eip55(&s);
        let sum = sum.trim_start_matches("0x");
        if sum != address {
            Err(Eip55Err::InvalidChecksum)
        } else {
            Ok(s)
        }
    }
}

fn parse_starknet(address: &str) -> Result<[u8; 32], Eip55Err> {
    use hex::FromHex;
    if !address.starts_with("0x") {
        Err(Eip55Err::MissingPrefix)
    } else {
        let s = <[u8; 32]>::from_hex(address)?;
        let sum = eip55(&s);
        let sum = sum.trim_start_matches("0x");
        if sum != address {
            Err(Eip55Err::InvalidChecksum)
        } else {
            Ok(s)
        }
    }
}
