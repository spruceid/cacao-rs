use leb128::read::Error as Leb128Error;
use std::io::{Error as IoError, Read, Write};

const VARSIG_VARINT_PREFIX: u8 = 0x68;

#[derive(Debug, Clone, PartialEq)]
pub struct VarSig {
    codec: u64,
    hash: u64,
    key_type: u64,
    signature: Vec<u8>,
}

impl VarSig {
    pub fn new(codec: u64, hash: u64, key_type: u64, signature: Vec<u8>) -> Self {
        Self {
            codec,
            hash,
            key_type,
            signature,
        }
    }

    pub fn codec(&self) -> u64 {
        self.codec
    }

    pub fn hash(&self) -> u64 {
        self.hash
    }

    pub fn key_type(&self) -> u64 {
        self.key_type
    }

    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    pub fn from_reader<R>(mut reader: &R) -> Result<Self, Leb128Error>
    where
        R: ?Sized + Read,
    {
        todo!()
    }

    pub fn to_writer<W>(&self, mut writer: &W) -> Result<usize, IoError>
    where
        W: ?Sized + Write,
    {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {}
}
