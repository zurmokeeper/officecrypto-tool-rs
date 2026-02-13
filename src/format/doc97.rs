use crate::error::Result;

/// Parse FibBase structure from Word document
pub fn parse_fib_base(data: &[u8]) -> Result<FibBase> {
    if data.len() < 32 {
        return Err(crate::error::OfficeCryptoError::InvalidFileFormat);
    }

    let f_encrypted = (data[11] & 0x01) != 0;

    Ok(FibBase { f_encrypted })
}

#[derive(Debug)]
pub struct FibBase {
    pub f_encrypted: bool,
}

/// Check if Word document is encrypted
pub fn is_encrypted(word_document_data: &[u8]) -> Result<bool> {
    let fib_base = parse_fib_base(word_document_data)?;
    Ok(fib_base.f_encrypted)
}

/// Decrypt Word 97 document
pub fn decrypt_document(
    _word_document_data: &[u8],
    _password: &str,
    _original_cfb: &[u8],
) -> Result<Vec<u8>> {
    // Word 97 decryption implementation would go here
    // Similar structure to XLS97 but with Word-specific record parsing
    Err(crate::error::OfficeCryptoError::UnsupportedAlgorithm(
        "Word 97 decryption not yet implemented".to_string(),
    ))
}
