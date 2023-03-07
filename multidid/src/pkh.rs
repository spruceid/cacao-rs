use crate::Error;
use std::io::{Error as IoError, Read, Write};

pub(crate) const PKH_CODEC: u64 = 0xca;

#[derive(Debug, Clone, PartialEq)]
pub enum DidPkhTypes {
    Eip { chain_id: u64, address: [u8; 20] },
}

impl std::fmt::Display for DidPkhTypes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // TODO correct address formatting
            Self::Eip { chain_id, address } => {
                todo!()
            }
        }
    }
}

impl DidPkhTypes {
    pub fn codec(&self) -> u64 {
        PKH_CODEC
    }
    pub(crate) fn from_reader<R>(reader: &mut R) -> Result<Self, Error>
    where
        R: Read,
    {
        todo!()
    }

    pub(crate) fn to_writer<W>(&self, writer: &mut W) -> Result<(), IoError>
    where
        W: ?Sized + Write,
    {
        todo!()
    }
}
