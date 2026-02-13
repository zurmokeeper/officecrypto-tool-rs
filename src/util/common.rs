use crate::error::{OfficeCryptoError, Result};

/// Parse encryption info version
pub fn parse_crypto_version(data: &[u8]) -> Result<(u16, u16)> {
    if data.len() < 4 {
        return Err(OfficeCryptoError::InvalidEncryptionInfo);
    }
    let major = u16::from_le_bytes([data[0], data[1]]);
    let minor = u16::from_le_bytes([data[2], data[3]]);
    Ok((major, minor))
}

/// Create a buffer with a u32 value in little-endian format
pub fn create_u32le_buffer(value: u32, size: usize) -> Vec<u8> {
    let mut buffer = vec![0u8; size];
    buffer[..4].copy_from_slice(&value.to_le_bytes());
    buffer
}

/// XOR two byte slices
pub fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

/// Parse encryption info from CFB entry
pub fn parse_encryption_info(data: &[u8]) -> Result<EncryptionInfo> {
    if data.len() < 8 {
        return Err(OfficeCryptoError::InvalidEncryptionInfo);
    }

    let (major, minor) = parse_crypto_version(&data[0..4])?;

    match minor {
        0x02 => parse_encryption_info_standard(data),
        0x03 => Ok(EncryptionInfo::Extensible),
        0x04 => Ok(EncryptionInfo::Agile),
        _ => Err(OfficeCryptoError::UnsupportedAlgorithm(format!(
            "Version {}.{}",
            major, minor
        ))),
    }
}

#[derive(Debug, Clone)]
pub enum EncryptionInfo {
    Standard {
        flags: u32,
        alg_id: u32,
        alg_id_hash: u32,
        key_size: u32,
        provider_type: u32,
        salt: Vec<u8>,
        verifier: Vec<u8>,
        verifier_hash: Vec<u8>,
    },
    Agile,
    Extensible,
}

fn parse_encryption_info_standard(data: &[u8]) -> Result<EncryptionInfo> {
    let mut pos = 4; // Skip version

    // Parse flags
    if data.len() < pos + 4 {
        return Err(OfficeCryptoError::InvalidEncryptionInfo);
    }
    let flags = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
    pos += 4;

    if (flags & 0x3F) != 0x24 {
        return Err(OfficeCryptoError::InvalidEncryptionInfo);
    }

    // Parse header size
    if data.len() < pos + 4 {
        return Err(OfficeCryptoError::InvalidEncryptionInfo);
    }
    let header_size = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
    pos += 4;

    // Parse encryption header
    let header_end = pos + header_size as usize;
    if data.len() < header_end {
        return Err(OfficeCryptoError::InvalidEncryptionInfo);
    }

    let header_flags = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
    pos += 8; // Skip flags and size_extra

    let alg_id = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
    pos += 4;

    let alg_id_hash = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
    pos += 4;

    let key_size = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
    pos += 4;

    let provider_type = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
    pos += 8; // Skip reserved fields

    // Skip CSP name (rest of header)
    pos = header_end;

    // Parse encryption verifier
    pos += 4; // Skip salt size

    let salt = data[pos..pos + 16].to_vec();
    pos += 16;

    let verifier = data[pos..pos + 16].to_vec();
    pos += 16;

    let _verifier_hash_size = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
    pos += 4;

    let verifier_hash = data[pos..pos + 32].to_vec();

    Ok(EncryptionInfo::Standard {
        flags: header_flags & 0x3F,
        alg_id,
        alg_id_hash,
        key_size,
        provider_type,
        salt,
        verifier,
        verifier_hash,
    })
}

/// Validate if data is a valid ZIP file
pub fn is_valid_zip(data: &[u8]) -> bool {
    // Check for ZIP file signature
    if data.len() < 4 {
        return false;
    }
    // PK\x03\x04 (local file header) or PK\x05\x06 (end of central directory)
    (data[0] == 0x50 && data[1] == 0x4B && data[2] == 0x03 && data[3] == 0x04)
        || (data[0] == 0x50 && data[1] == 0x4B && data[2] == 0x05 && data[3] == 0x06)
}
