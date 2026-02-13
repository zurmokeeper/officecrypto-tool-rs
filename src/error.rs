use thiserror::Error;

#[derive(Error, Debug)]
pub enum OfficeCryptoError {
    #[error("Invalid password")]
    InvalidPassword,

    #[error("Input must be a valid buffer")]
    InvalidInput,

    #[error("Password is required")]
    PasswordRequired,

    #[error("Password length exceeds maximum of 255 characters")]
    PasswordTooLong,

    #[error("Unsupported encryption algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("Invalid encryption info")]
    InvalidEncryptionInfo,

    #[error("CFB parsing error: {0}")]
    CfbError(String),

    #[error("XML parsing error: {0}")]
    XmlError(String),

    #[error("Invalid file format")]
    InvalidFileFormat,

    #[error("Encryption info not found")]
    EncryptionInfoNotFound,

    #[error("Decrypted data is not a valid ZIP file")]
    InvalidZipFile,

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("UTF-8 encoding error: {0}")]
    Utf8Error(#[from] std::string::FromUtf8Error),

    #[error("Base64 decoding error: {0}")]
    Base64Error(#[from] base64::DecodeError),

    #[error("ZIP error: {0}")]
    ZipError(String),

    #[error("Other error: {0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, OfficeCryptoError>;

// CFB errors are now handled directly as io::Error

impl From<quick_xml::Error> for OfficeCryptoError {
    fn from(err: quick_xml::Error) -> Self {
        OfficeCryptoError::XmlError(err.to_string())
    }
}
