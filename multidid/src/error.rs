use crate::{key, pkh};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Pkh(#[from] pkh::Error),
    #[error(transparent)]
    Key(#[from] key::Error),
    #[error(transparent)]
    Varint(#[from] unsigned_varint::io::ReadError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("Invalid multidid varint prefix, expected 0x9d1a, recieved {0:x}")]
    InvalidPrefix(u64),
    #[error(transparent)]
    Parameter(#[from] iri_string::validate::Error),
    #[error(transparent)]
    DidParse(#[from] std::string::FromUtf8Error),
    #[error("multidid formatting error: {0}")]
    Format(&'static str),
}
