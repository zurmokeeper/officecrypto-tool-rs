pub mod crypto;
pub mod error;
pub mod format;
pub mod util;

pub use error::{OfficeCryptoError, Result};

use cfb::CompoundFile;
use std::io::Cursor;

/// Encryption type for encrypt function
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionType {
    /// ECMA-376 Standard encryption (AES-128-ECB)
    Standard,
    /// ECMA-376 Agile encryption (AES-256-CBC)
    Agile,
}

impl Default for EncryptionType {
    fn default() -> Self {
        EncryptionType::Agile
    }
}

/// Decrypt an Office file with password
///
/// # Arguments
///
/// * `input` - The encrypted file data
/// * `password` - The password to decrypt
///
/// # Returns
///
/// Decrypted file data or error
///
/// # Examples
///
/// ```no_run
/// use officecrypto_tool::decrypt;
/// use std::fs;
///
/// let input = fs::read("encrypted.xlsx").unwrap();
/// let output = decrypt(&input, "password123").unwrap();
/// fs::write("decrypted.xlsx", output).unwrap();
/// ```
pub fn decrypt(input: &[u8], password: &str) -> Result<Vec<u8>> {
    if input.is_empty() {
        return Err(OfficeCryptoError::InvalidInput);
    }

    if password.is_empty() {
        return Err(OfficeCryptoError::PasswordRequired);
    }

    // Parse CFB
    let mut cursor = Cursor::new(input);
    let mut cfb = CompoundFile::open(&mut cursor)?;

    // Check for EncryptionInfo (OOXML formats)
    if let Ok(mut encryption_info_stream) = cfb.open_stream("/EncryptionInfo") {
        let mut encryption_info = Vec::new();
        std::io::Read::read_to_end(&mut encryption_info_stream, &mut encryption_info)?;

        let mut encrypted_package_stream = cfb.open_stream("/EncryptedPackage")?;
        let mut encrypted_package = Vec::new();
        std::io::Read::read_to_end(&mut encrypted_package_stream, &mut encrypted_package)?;

        // Parse encryption type
        let einfo = util::parse_encryption_info(&encryption_info)?;

        match einfo {
            util::EncryptionInfo::Standard {
                alg_id,
                alg_id_hash,
                key_size,
                provider_type,
                salt,
                verifier,
                verifier_hash,
                ..
            } => {
                // ECMA-376 Standard
                let key = crypto::ecma376_standard::convert_password_to_key(
                    password,
                    alg_id,
                    alg_id_hash,
                    provider_type,
                    key_size,
                    16,
                    &salt,
                )?;

                let valid =
                    crypto::ecma376_standard::verify_key(&key, &verifier, &verifier_hash)?;
                if !valid {
                    return Err(OfficeCryptoError::InvalidPassword);
                }

                let output = crypto::ecma376_standard::decrypt(&key, &encrypted_package)?;
                return Ok(output);
            }
            util::EncryptionInfo::Agile => {
                // ECMA-376 Agile
                let output = crypto::ecma376_agile::decrypt(
                    &encryption_info,
                    &encrypted_package,
                    password,
                )?;
                return Ok(output);
            }
            util::EncryptionInfo::Extensible => {
                return Err(OfficeCryptoError::UnsupportedAlgorithm(
                    "Extensible".to_string(),
                ));
            }
        }
    }

    // If no EncryptionInfo, check for legacy Office 97 formats
    // Check for Workbook stream (Excel 97-2003)
    if let Ok(mut workbook_stream) = cfb.open_stream("/Workbook")
        .or_else(|_| cfb.open_stream("/Book"))
    {
        let mut workbook_data = Vec::new();
        std::io::Read::read_to_end(&mut workbook_stream, &mut workbook_data)?;

        // Check if encrypted
        if format::is_xls_encrypted(&workbook_data)? {
            let decrypted = format::decrypt_workbook(&workbook_data, password, input)?;
            return Ok(decrypted);
        }
    }

    // Check for WordDocument stream (Word 97-2003)
    if let Ok(mut word_stream) = cfb.open_stream("/WordDocument") {
        let mut word_data = Vec::new();
        std::io::Read::read_to_end(&mut word_stream, &mut word_data)?;

        // Check if encrypted
        if format::is_doc_encrypted(&word_data)? {
            let decrypted = format::doc97::decrypt_document(&word_data, password, input)?;
            return Ok(decrypted);
        }
    }

    // Check for PowerPoint Document stream (PowerPoint 97-2003)
    if let Ok(mut ppt_stream) = cfb.open_stream("/PowerPoint Document") {
        let mut ppt_data = Vec::new();
        std::io::Read::read_to_end(&mut ppt_stream, &mut ppt_data)?;

        // Check for Current User stream
        if let Ok(mut current_user_stream) = cfb.open_stream("/Current User") {
            let mut current_user_data = Vec::new();
            std::io::Read::read_to_end(&mut current_user_stream, &mut current_user_data)?;

            if format::is_ppt_encrypted(&ppt_data, &current_user_data)? {
                let decrypted = format::ppt97::decrypt_presentation(&ppt_data, password, input)?;
                return Ok(decrypted);
            }
        }
    }

    // If no EncryptionInfo and not legacy encrypted, return original
    Ok(input.to_vec())
}

/// Encrypt an Office file with password
///
/// # Arguments
///
/// * `input` - The file data to encrypt
/// * `password` - The password for encryption
/// * `encryption_type` - The encryption type to use (default: Agile)
///
/// # Returns
///
/// Encrypted file data or error
///
/// # Examples
///
/// ```no_run
/// use officecrypto_tool::{encrypt, EncryptionType};
/// use std::fs;
///
/// let input = fs::read("document.xlsx").unwrap();
/// let output = encrypt(&input, "password123", EncryptionType::Agile).unwrap();
/// fs::write("encrypted.xlsx", output).unwrap();
/// ```
pub fn encrypt(
    input: &[u8],
    password: &str,
    encryption_type: EncryptionType,
) -> Result<Vec<u8>> {
    if input.is_empty() {
        return Err(OfficeCryptoError::InvalidInput);
    }

    if password.is_empty() {
        return Err(OfficeCryptoError::PasswordRequired);
    }

    if password.len() > 255 {
        return Err(OfficeCryptoError::PasswordTooLong);
    }

    match encryption_type {
        EncryptionType::Standard => crypto::ecma376_standard::encrypt_standard(input, password),
        EncryptionType::Agile => {
            Err(OfficeCryptoError::UnsupportedAlgorithm(
                "Agile encryption not yet implemented".to_string(),
            ))
        }
    }
}

/// Check if an Office file is encrypted
///
/// # Arguments
///
/// * `input` - The file data to check
///
/// # Returns
///
/// `true` if encrypted, `false` otherwise
///
/// # Examples
///
/// ```no_run
/// use officecrypto_tool::is_encrypted;
/// use std::fs;
///
/// let input = fs::read("document.xlsx").unwrap();
/// if is_encrypted(&input).unwrap() {
///     println!("File is encrypted");
/// }
/// ```
pub fn is_encrypted(input: &[u8]) -> Result<bool> {
    if input.is_empty() {
        return Ok(false);
    }

    // Parse CFB
    let mut cursor = Cursor::new(input);
    let mut cfb = match CompoundFile::open(&mut cursor) {
        Ok(cfb) => cfb,
        Err(_) => return Ok(false),
    };

    // Check for EncryptionInfo
    if cfb.open_stream("/EncryptionInfo").is_ok() {
        return Ok(true);
    }

    // TODO: Check for legacy format encryption (XLS97, DOC97, PPT97)
    // For now, assume not encrypted
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_encrypted_invalid_input() {
        let result = is_encrypted(&[]);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_decrypt_empty_password() {
        let input = vec![1, 2, 3];
        let result = decrypt(&input, "");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            OfficeCryptoError::PasswordRequired
        ));
    }

    #[test]
    fn test_encrypt_password_too_long() {
        let input = vec![1, 2, 3];
        let long_password = "a".repeat(256);
        let result = encrypt(&input, &long_password, EncryptionType::Standard);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            OfficeCryptoError::PasswordTooLong
        ));
    }
}
