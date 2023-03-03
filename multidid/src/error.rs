#[derive(Debug, thiserror::Error)]
pub enum Error {
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
}
