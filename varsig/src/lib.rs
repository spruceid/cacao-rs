use std::io::{Error as IoError, Read, Write};
use unsigned_varint::{
    encode::{u64 as write_u64, u64_buffer},
    io::read_u64,
};

const VARSIG_VARINT_PREFIX: u8 = 0x68;

#[derive(Debug, Clone, PartialEq)]
pub struct VarSig {
    codec: u64,
    hash: u64,
    key_type: u64,
    signature: Vec<u8>,
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Varint(#[from] unsigned_varint::io::ReadError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("Invalid varsig prefix, expected 0x68, recieved {0:x}")]
    InvalidPrefix(u8),
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

    pub fn to_vec(&self) -> Result<Vec<u8>, IoError> {
        let mut buf = Vec::new();
        self.to_writer(&mut buf)?;
        Ok(buf)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Self::from_reader(&mut bytes.as_ref())
    }

    pub fn from_reader<R>(reader: &mut R) -> Result<Self, Error>
    where
        R: Read,
    {
        let mut tag = [0u8; 1];
        reader.read_exact(&mut tag)?;

        if tag[0] != VARSIG_VARINT_PREFIX {
            return Err(Error::InvalidPrefix(tag[0]));
        };

        println!("tag: {:#x?}", tag);
        let codec = read_u64(reader.by_ref())?;
        println!("codec: {:#x?}", codec);
        let hash = read_u64(reader.by_ref())?;
        println!("hash: {:#x?}", hash);
        let key_type = read_u64(reader.by_ref())?;
        println!("key_type: {:#x?}", key_type);

        let sig_len = read_u64(reader.by_ref())?;
        println!("sig_len: {:#x?}", sig_len);
        let mut signature = vec![0; sig_len as usize];
        reader.read_exact(&mut signature)?;
        println!("signature: {:#x?}", signature);

        Ok(Self::new(codec, hash, key_type, signature))
    }

    pub fn to_writer<W>(&self, writer: &mut W) -> Result<(), IoError>
    where
        W: ?Sized + Write,
    {
        writer.write(&[VARSIG_VARINT_PREFIX; 1])?;
        let mut buf = u64_buffer();
        writer.write(write_u64(self.codec, &mut buf))?;
        writer.write(write_u64(self.hash, &mut buf))?;
        writer.write(write_u64(self.key_type, &mut buf))?;
        writer.write(write_u64(self.signature.len() as u64, &mut buf))?;
        writer.write(&self.signature)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: [u8; 15] = [
        0x68, 0xd2, 0x04, 0xda, 0x03, 0x24, 0xde, 0xb7, 0xde, 0x9a, 0xf1, 0xd9, 0xa2, 0xa3, 0x02,
    ];

    #[test]
    fn basic_roundtrip() {
        let varsig = VarSig::from_reader(&mut EXAMPLE.as_ref()).unwrap();
        assert_eq!(varsig.codec(), 0x04d2);
        assert_eq!(varsig.hash(), 0x03da);
        assert_eq!(varsig.key_type(), 0x24);
        assert_eq!(varsig.signature(), &EXAMPLE[6..]);

        assert_eq!(&varsig.to_vec().unwrap(), &EXAMPLE);
    }

    #[test]
    fn reverse_roundtrip() {
        let varsig = VarSig::new(0x0129, 0x12, 0xed, EXAMPLE[6..].to_vec());
        let encoded = varsig.to_vec().unwrap();
        let decoded = VarSig::from_bytes(&encoded.as_ref()).unwrap();
        assert_eq!(varsig, decoded);
    }

    #[test]
    fn basic_ser() {
        let varsig = VarSig::new(0x0129, 0x12, 0xed, EXAMPLE[6..].to_vec());
        assert_eq!(&varsig.to_vec().unwrap(), &EXAMPLE);
    }

    #[test]
    fn rsad() {
        let b = [0xd2, 0x04];
        println!("{:#x?}", read_u64(&mut b.as_ref()));
        None::<u8>.unwrap();
    }
}