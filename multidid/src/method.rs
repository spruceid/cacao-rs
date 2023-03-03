use crate::{DidKeyTypes, Error};
use std::io::{Error as IoError, Read, Write};
use unsigned_varint::{
    encode::{u64 as write_u64, u64_buffer},
    io::read_u64,
};

const RAW_CODEC: u64 = 0x55;
const PKH_CODEC: u64 = 0xca;

#[derive(Debug, Clone, PartialEq)]
pub enum Method {
    Pkh(Vec<u8>),
    Key(DidKeyTypes),
    Raw(String),
}

impl Method {
    pub fn codec(&self) -> u64 {
        use Method::*;
        match self {
            Raw(_) => RAW_CODEC,
            Pkh(_) => PKH_CODEC,
            Key(k) => k.codec(),
        }
    }

    pub(crate) fn from_reader<R: Read>(reader: &mut R) -> Result<Self, Error> {
        let codec = read_u64(reader.by_ref())?;
        match codec {
            RAW_CODEC => {
                let len = read_u64(reader.by_ref())?;
                let mut buf = vec![0; len as usize];
                reader.read_exact(&mut buf)?;
                Ok(Self::Raw(String::from_utf8(buf)?))
            }
            PKH_CODEC => {
                let len = read_u64(reader.by_ref())?;
                let mut buf = vec![0; len as usize];
                reader.read_exact(&mut buf)?;
                Ok(Self::Pkh(buf))
            }
            codec => {
                let key = DidKeyTypes::from_reader(reader, codec)?;
                Ok(Self::Key(key))
            }
        }
    }

    pub(crate) fn to_writer<W: Write>(&self, writer: &mut W) -> Result<(), IoError> {
        match self {
            Self::Raw(buf) => {
                writer.write_all(buf.as_bytes())?;
            }
            Self::Pkh(buf) => {
                let mut vi_buf = u64_buffer();
                writer.write_all(write_u64(buf.len() as u64, &mut vi_buf))?;
                writer.write_all(buf)?;
            }
            Self::Key(key) => {
                key.to_writer(writer)?;
            }
        }
        Ok(())
    }
}
