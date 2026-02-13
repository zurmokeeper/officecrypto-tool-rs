use crate::crypto::{rc4, rc4_cryptoapi, xor_obfuscation};
use crate::error::{OfficeCryptoError, Result};

// Record type numbers
const RECORD_BOF: u16 = 2057;
const RECORD_FILE_PASS: u16 = 47;
const RECORD_WRITE_PROTECT: u16 = 134;
const RECORD_BOUND_SHEET8: u16 = 133;
const RECORD_INTERFACE_HDR: u16 = 225;
const RECORD_RRD_INFO: u16 = 406;
const RECORD_RRD_HEAD: u16 = 312;
const RECORD_USR_EXCL: u16 = 404;
const RECORD_FILE_LOCK: u16 = 405;

// File format versions
const FORMAT_BIFF5: u16 = 1280;
const FORMAT_BIFF8: u16 = 1536;

#[derive(Debug, Clone)]
pub enum EncryptionType {
    Xor,
    Rc4,
    Rc4CryptoApi { key_size: u32 },
}

#[derive(Debug)]
struct Record {
    num: u16,
    size: u16,
    data: Vec<u8>,
}

/// Parse records from workbook stream
fn parse_records(data: &[u8]) -> Result<Vec<Record>> {
    let mut records = Vec::new();
    let mut pos = 0;

    while pos + 4 <= data.len() {
        let num = u16::from_le_bytes([data[pos], data[pos + 1]]);
        let size = u16::from_le_bytes([data[pos + 2], data[pos + 3]]);
        pos += 4;

        if pos + size as usize > data.len() {
            break;
        }

        let record_data = data[pos..pos + size as usize].to_vec();
        records.push(Record {
            num,
            size,
            data: record_data,
        });

        pos += size as usize;
    }

    Ok(records)
}

/// Check if workbook is encrypted
pub fn is_encrypted(workbook_data: &[u8]) -> Result<bool> {
    if workbook_data.len() < 4 {
        return Ok(false);
    }

    let mut pos = 0;

    // Read BOF record
    let _bof = u16::from_le_bytes([workbook_data[pos], workbook_data[pos + 1]]);
    let bof_size = u16::from_le_bytes([workbook_data[pos + 2], workbook_data[pos + 3]]);
    pos += 4 + bof_size as usize;

    if pos + 4 > workbook_data.len() {
        return Ok(false);
    }

    // Check next record
    let mut record = u16::from_le_bytes([workbook_data[pos], workbook_data[pos + 1]]);

    // Skip WriteProtect if present
    if record == RECORD_WRITE_PROTECT {
        let write_protect_size = u16::from_le_bytes([workbook_data[pos + 2], workbook_data[pos + 3]]);
        pos += 4 + write_protect_size as usize;

        if pos + 2 > workbook_data.len() {
            return Ok(false);
        }

        record = u16::from_le_bytes([workbook_data[pos], workbook_data[pos + 1]]);
    }

    // Check for FilePass record
    Ok(record == RECORD_FILE_PASS)
}

/// Decrypt XLS97 workbook
pub fn decrypt_workbook(
    workbook_data: &[u8],
    password: &str,
    _original_cfb: &[u8],
) -> Result<Vec<u8>> {
    let records = parse_records(workbook_data)?;

    // Find FilePass record
    let file_pass = records
        .iter()
        .find(|r| r.num == RECORD_FILE_PASS)
        .ok_or(OfficeCryptoError::EncryptionInfoNotFound)?;

    // Parse encryption type
    let encryption_type = if file_pass.data.len() < 2 {
        return Err(OfficeCryptoError::InvalidEncryptionInfo);
    };

    let w_encryption_type = u16::from_le_bytes([file_pass.data[0], file_pass.data[1]]);

    let enc_type = match w_encryption_type {
        0x0000 => {
            // XOR obfuscation
            if file_pass.data.len() < 6 {
                return Err(OfficeCryptoError::InvalidEncryptionInfo);
            }
            let _key = u16::from_le_bytes([file_pass.data[2], file_pass.data[3]]);
            let verification_bytes = u16::from_le_bytes([file_pass.data[4], file_pass.data[5]]);

            // Verify password
            if !xor_obfuscation::verify_password(password, verification_bytes)? {
                return Err(OfficeCryptoError::InvalidPassword);
            }

            EncryptionType::Xor
        }
        0x0001 => {
            // RC4 encryption
            if file_pass.data.len() < 6 {
                return Err(OfficeCryptoError::InvalidEncryptionInfo);
            }

            let v_major = u16::from_le_bytes([file_pass.data[2], file_pass.data[3]]);
            let v_minor = u16::from_le_bytes([file_pass.data[4], file_pass.data[5]]);

            if v_major == 0x0001 && v_minor == 0x0001 {
                // RC4
                if file_pass.data.len() < 54 {
                    return Err(OfficeCryptoError::InvalidEncryptionInfo);
                }

                let salt = file_pass.data[6..22].to_vec();
                let encrypted_verifier = file_pass.data[22..38].to_vec();
                let encrypted_verifier_hash = file_pass.data[38..54].to_vec();

                // Verify password
                if !rc4::verify_password(password, &salt, &encrypted_verifier, &encrypted_verifier_hash)? {
                    return Err(OfficeCryptoError::InvalidPassword);
                }

                EncryptionType::Rc4
            } else if [0x0002, 0x0003, 0x0004].contains(&v_major) && v_minor == 0x0002 {
                // RC4 CryptoAPI
                if file_pass.data.len() < 10 {
                    return Err(OfficeCryptoError::InvalidEncryptionInfo);
                }

                let _flags = u32::from_le_bytes([
                    file_pass.data[6],
                    file_pass.data[7],
                    file_pass.data[8],
                    file_pass.data[9],
                ]);

                let header_size = u32::from_le_bytes([
                    file_pass.data[10],
                    file_pass.data[11],
                    file_pass.data[12],
                    file_pass.data[13],
                ]) as usize;

                let header_end = 14 + header_size;
                if file_pass.data.len() < header_end + 24 {
                    return Err(OfficeCryptoError::InvalidEncryptionInfo);
                }

                // Parse header
                let key_size = u32::from_le_bytes([
                    file_pass.data[30],
                    file_pass.data[31],
                    file_pass.data[32],
                    file_pass.data[33],
                ]);

                // Parse verifier
                let verifier_start = header_end;
                let _salt_size = u32::from_le_bytes([
                    file_pass.data[verifier_start],
                    file_pass.data[verifier_start + 1],
                    file_pass.data[verifier_start + 2],
                    file_pass.data[verifier_start + 3],
                ]);

                let salt = file_pass.data[verifier_start + 4..verifier_start + 20].to_vec();
                let encrypted_verifier = file_pass.data[verifier_start + 20..verifier_start + 36].to_vec();
                let verifier_hash_size = u32::from_le_bytes([
                    file_pass.data[verifier_start + 36],
                    file_pass.data[verifier_start + 37],
                    file_pass.data[verifier_start + 38],
                    file_pass.data[verifier_start + 39],
                ]) as usize;

                let encrypted_verifier_hash = file_pass.data
                    [verifier_start + 40..verifier_start + 40 + verifier_hash_size]
                    .to_vec();

                // Verify password
                if !rc4_cryptoapi::verify_password(
                    password,
                    &salt,
                    key_size,
                    &encrypted_verifier,
                    &encrypted_verifier_hash,
                )? {
                    return Err(OfficeCryptoError::InvalidPassword);
                }

                EncryptionType::Rc4CryptoApi { key_size }
            } else {
                return Err(OfficeCryptoError::UnsupportedAlgorithm(format!(
                    "RC4 version {}.{}",
                    v_major, v_minor
                )));
            }
        }
        _ => {
            return Err(OfficeCryptoError::UnsupportedAlgorithm(format!(
                "Encryption type 0x{:04X}",
                w_encryption_type
            )));
        }
    };

    // Build plaintext markers and encrypted buffer
    let mut plaintext_markers = Vec::new();
    let mut encrypted_buffer = Vec::new();

    for record in &records {
        // These records are not encrypted
        if [
            RECORD_BOF,
            RECORD_FILE_PASS,
            RECORD_USR_EXCL,
            RECORD_FILE_LOCK,
            RECORD_INTERFACE_HDR,
            RECORD_RRD_INFO,
            RECORD_RRD_HEAD,
        ]
        .contains(&record.num)
        {
            // Header
            plaintext_markers.extend(vec![0; 4]);
            encrypted_buffer.extend(vec![0u8; 4]);

            // Data
            plaintext_markers.extend(vec![0; record.data.len()]);
            encrypted_buffer.extend(vec![0u8; record.data.len()]);
        } else if record.num == RECORD_BOUND_SHEET8 {
            // First 4 bytes of BoundSheet8 are not encrypted
            plaintext_markers.extend(vec![0; 4]); // Header
            encrypted_buffer.extend(vec![0u8; 4]);

            plaintext_markers.extend(vec![0; 4]); // lbPlyPos
            encrypted_buffer.extend(vec![0u8; 4]);

            // Rest is encrypted
            plaintext_markers.extend(vec![-2i8; record.data.len() - 4]);
            encrypted_buffer.extend(&record.data[4..]);
        } else {
            // Header not encrypted
            plaintext_markers.extend(vec![0; 4]);
            encrypted_buffer.extend(vec![0u8; 4]);

            // Data is encrypted
            plaintext_markers.extend(vec![-1i8; record.data.len()]);
            encrypted_buffer.extend(&record.data);
        }
    }

    // Decrypt based on type
    let decrypted = match enc_type {
        EncryptionType::Xor => {
            xor_obfuscation::decrypt(password, &encrypted_buffer, &plaintext_markers)?
        }
        EncryptionType::Rc4 => {
            let salt = file_pass.data[6..22].to_vec();
            let dec = rc4::decrypt(password, &salt, &encrypted_buffer, 1024)?;

            // Apply plaintext markers
            let mut output = Vec::new();
            for (i, &marker) in plaintext_markers.iter().enumerate() {
                if i < dec.len() {
                    output.push(if marker == 0 || marker == -2 {
                        workbook_data[i]
                    } else {
                        dec[i]
                    });
                }
            }
            output
        }
        EncryptionType::Rc4CryptoApi { key_size } => {
            let verifier_start = 14 + file_pass.data[10] as usize;
            let salt = file_pass.data[verifier_start + 4..verifier_start + 20].to_vec();
            let dec = rc4_cryptoapi::decrypt(password, &salt, key_size, &encrypted_buffer, 1024)?;

            // Apply plaintext markers
            let mut output = Vec::new();
            for (i, &marker) in plaintext_markers.iter().enumerate() {
                if i < dec.len() {
                    output.push(if marker == 0 || marker == -2 {
                        workbook_data[i]
                    } else {
                        dec[i]
                    });
                }
            }
            output
        }
    };

    // Reconstruct CFB with decrypted workbook
    // For now, return the decrypted workbook data
    // In a full implementation, we would rebuild the entire CFB structure
    Ok(decrypted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_records() {
        // Simple BOF record: type=2057, size=16, data=[16 bytes]
        let data = vec![
            0x09, 0x08, 0x10, 0x00, // BOF record
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 16 bytes data
        ];
        let records = parse_records(&data).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].num, 2057);
        assert_eq!(records[0].size, 16);
    }
}
