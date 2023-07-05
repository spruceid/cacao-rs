use crate::Error;
use std::io::{Error as IoError, Read, Write};
use unsigned_varint::{
    encode::{u64 as write_u64, u64_buffer},
    io::read_u64,
};

pub(crate) const PKH_CODEC: u64 = 0xca;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DidPkhTypes {
    Bip122(Caip10<[u8; 32], [u8; 25]>),
    Eip155(Caip10<String, [u8; 20]>),
    Cosmos(Caip10<String, CosmosAddress>),
    Starknet(Caip10<String, [u8; 20]>),
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

    pub fn to_vec(&self) -> Vec<u8> {
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
                vec.extend(write_u64(caip10.chain_id().len() as u64, &mut buf));
                vec.extend(caip10.chain_id().as_bytes());
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

    pub fn from_reader<R>(reader: &mut R) -> Result<Self, Error>
    where
        R: Read,
    {
        let mut buf = [0u8; 1];
        reader.read_exact(&mut buf)?;
        let codec = buf[0];
        if codec as u64 != PKH_CODEC {
            return Err(Error::InvalidCodec(codec as u64));
        }
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
                let ref_len = read_u64(reader.by_ref())?;
                let mut chain_id = vec![0u8; ref_len as usize];
                reader.read_exact(&mut chain_id)?;
                let mut address = [0u8; 20];
                reader.read_exact(&mut address)?;
                Ok(DidPkhTypes::Eip155(Caip10::new(
                    String::from_utf8(chain_id)?,
                    address,
                )))
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
                        _ => return Err(Error::Format("Invalid cosmos address length")),
                    },
                )))
            }
            // starknet
            4 => {
                let ref_len = read_u64(reader.by_ref())?;
                let mut chain_id = vec![0u8; ref_len as usize];
                reader.read_exact(&mut chain_id)?;
                let mut address = [0u8; 20];
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
                        _ => return Err(Error::Format("Invalid hedera address length")),
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
            _ => Err(Error::Format("Unsupported did-pkh discriminant")),
        }
    }

    pub fn to_writer<W>(&self, writer: &mut W) -> Result<(), IoError>
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
                writer.write_all(write_u64(caip10.chain_id().len() as u64, &mut buf))?;
                writer.write_all(caip10.chain_id().as_bytes())?;
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
