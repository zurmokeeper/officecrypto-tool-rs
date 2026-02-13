use crate::error::{OfficeCryptoError, Result};
use crate::util::{create_u32le_buffer, is_valid_zip};
use aes::Aes256;
use cbc::{Decryptor, Encryptor};
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::Hmac;
use quick_xml::events::Event;
use quick_xml::Reader;
use sha2::{Digest, Sha512};
use std::collections::HashMap;
use base64::{Engine as _, engine::general_purpose};

const ENCRYPTION_INFO_PREFIX: &[u8] = &[0x04, 0x00, 0x04, 0x00, 0x40, 0x00, 0x00, 0x00];
const PACKAGE_ENCRYPTION_CHUNK_SIZE: usize = 4096;
const PACKAGE_OFFSET: usize = 8;

type Aes256Cbc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;
type HmacSha512 = Hmac<Sha512>;

// Block keys for encryption
struct BlockKeys;

impl BlockKeys {
    const KEY: &'static [u8] = &[0x14, 0x6e, 0x0b, 0xe7, 0xab, 0xac, 0xd0, 0xd6];
    const VERIFIER_HASH_INPUT: &'static [u8] = &[0xfe, 0xa7, 0xd2, 0x76, 0x3b, 0x4b, 0x9e, 0x79];
    const VERIFIER_HASH_VALUE: &'static [u8] = &[0xd7, 0xaa, 0x0f, 0x6d, 0x30, 0x61, 0x34, 0x4e];
    const DATA_INTEGRITY_HMAC_KEY: &'static [u8] =
        &[0x5f, 0xb2, 0xad, 0x01, 0x0c, 0xb9, 0xe1, 0xf6];
    const DATA_INTEGRITY_HMAC_VALUE: &'static [u8] =
        &[0xa0, 0x67, 0x7f, 0x02, 0xb2, 0x2c, 0x84, 0x33];
}

#[derive(Debug, Clone)]
pub struct AgileEncryptionInfo {
    pub package: PackageInfo,
    pub key: KeyInfo,
}

#[derive(Debug, Clone)]
pub struct PackageInfo {
    pub cipher_algorithm: String,
    pub cipher_chaining: String,
    pub salt_value: Vec<u8>,
    pub hash_algorithm: String,
    pub block_size: usize,
}

#[derive(Debug, Clone)]
pub struct KeyInfo {
    pub encrypted_key_value: Vec<u8>,
    pub encrypted_verifier_hash_input: Vec<u8>,
    pub encrypted_verifier_hash_value: Vec<u8>,
    pub cipher_algorithm: String,
    pub cipher_chaining: String,
    pub salt_value: Vec<u8>,
    pub hash_algorithm: String,
    pub spin_count: u32,
    pub key_bits: usize,
}

/// Parse agile encryption info from XML
pub fn parse_encryption_info(buffer: &[u8]) -> Result<AgileEncryptionInfo> {
    // Skip prefix
    if buffer.len() < ENCRYPTION_INFO_PREFIX.len() {
        return Err(OfficeCryptoError::InvalidEncryptionInfo);
    }

    let xml = &buffer[ENCRYPTION_INFO_PREFIX.len()..];
    let xml_str = std::str::from_utf8(xml)
        .map_err(|_| OfficeCryptoError::InvalidEncryptionInfo)?;

    let mut reader = Reader::from_str(xml_str);
    reader.trim_text(true);

    let mut package_info: Option<PackageInfo> = None;
    let mut key_info: Option<KeyInfo> = None;

    let mut buf = Vec::new();
    let mut current_element = String::new();
    let mut in_key_encryptor = false;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                current_element = name.clone();

                if name == "keyData" {
                    let mut attrs = HashMap::new();
                    for attr in e.attributes().filter_map(|a| a.ok()) {
                        let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                        let value = String::from_utf8_lossy(&attr.value).to_string();
                        attrs.insert(key, value);
                    }

                    package_info = Some(PackageInfo {
                        cipher_algorithm: attrs.get("cipherAlgorithm").unwrap_or(&"AES".to_string()).clone(),
                        cipher_chaining: attrs.get("cipherChaining").unwrap_or(&"ChainingModeCBC".to_string()).clone(),
                        salt_value: general_purpose::STANDARD.decode(attrs.get("saltValue").ok_or(OfficeCryptoError::InvalidEncryptionInfo)?)?,
                        hash_algorithm: attrs.get("hashAlgorithm").unwrap_or(&"SHA512".to_string()).clone(),
                        block_size: attrs.get("blockSize").and_then(|s| s.parse().ok()).unwrap_or(16),
                    });
                } else if name == "keyEncryptors" {
                    in_key_encryptor = true;
                } else if name == "encryptedKey" && in_key_encryptor {
                    let mut attrs = HashMap::new();
                    for attr in e.attributes().filter_map(|a| a.ok()) {
                        let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                        let value = String::from_utf8_lossy(&attr.value).to_string();
                        attrs.insert(key, value);
                    }

                    key_info = Some(KeyInfo {
                        encrypted_key_value: general_purpose::STANDARD.decode(attrs.get("encryptedKeyValue").ok_or(OfficeCryptoError::InvalidEncryptionInfo)?)?,
                        encrypted_verifier_hash_input: general_purpose::STANDARD.decode(attrs.get("encryptedVerifierHashInput").ok_or(OfficeCryptoError::InvalidEncryptionInfo)?)?,
                        encrypted_verifier_hash_value: general_purpose::STANDARD.decode(attrs.get("encryptedVerifierHashValue").ok_or(OfficeCryptoError::InvalidEncryptionInfo)?)?,
                        cipher_algorithm: attrs.get("cipherAlgorithm").unwrap_or(&"AES".to_string()).clone(),
                        cipher_chaining: attrs.get("cipherChaining").unwrap_or(&"ChainingModeCBC".to_string()).clone(),
                        salt_value: base64::decode(attrs.get("saltValue").ok_or(OfficeCryptoError::InvalidEncryptionInfo)?)?,
                        hash_algorithm: attrs.get("hashAlgorithm").unwrap_or(&"SHA512".to_string()).clone(),
                        spin_count: attrs.get("spinCount").and_then(|s| s.parse().ok()).unwrap_or(100000),
                        key_bits: attrs.get("keyBits").and_then(|s| s.parse().ok()).unwrap_or(256),
                    });
                }
            }
            Ok(Event::End(_)) => {
                current_element.clear();
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(OfficeCryptoError::XmlError(e.to_string())),
            _ => {}
        }
        buf.clear();
    }

    Ok(AgileEncryptionInfo {
        package: package_info.ok_or(OfficeCryptoError::InvalidEncryptionInfo)?,
        key: key_info.ok_or(OfficeCryptoError::InvalidEncryptionInfo)?,
    })
}

/// Convert password to encryption key
pub fn convert_password_to_key(
    password: &str,
    hash_algorithm: &str,
    salt_value: &[u8],
    spin_count: u32,
    key_bits: usize,
    block_key: &[u8],
) -> Result<Vec<u8>> {
    // Convert password to UTF-16LE
    let password_buffer: Vec<u8> = password
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();

    // Generate initial hash
    let mut key = hash_data(hash_algorithm, &[salt_value, &password_buffer])?;

    // Spin iterations
    for i in 0..spin_count {
        let iterator = create_u32le_buffer(i, 4);
        key = hash_data(hash_algorithm, &[&iterator, &key])?;
    }

    // Final hash with block key
    key = hash_data(hash_algorithm, &[&key, block_key])?;

    // Truncate or pad to key_bits
    let key_bytes = key_bits / 8;
    if key.len() < key_bytes {
        key.resize(key_bytes, 0x36);
    } else if key.len() > key_bytes {
        key.truncate(key_bytes);
    }

    Ok(key)
}

/// Hash data using specified algorithm
fn hash_data(algorithm: &str, buffers: &[&[u8]]) -> Result<Vec<u8>> {
    match algorithm.to_uppercase().as_str() {
        "SHA512" | "SHA-512" => {
            let mut hasher = Sha512::new();
            for buffer in buffers {
                hasher.update(buffer);
            }
            Ok(hasher.finalize().to_vec())
        }
        "SHA1" | "SHA-1" => {
            let mut hasher = sha1::Sha1::new();
            for buffer in buffers {
                hasher.update(buffer);
            }
            Ok(hasher.finalize().to_vec())
        }
        _ => Err(OfficeCryptoError::UnsupportedAlgorithm(
            algorithm.to_string(),
        )),
    }
}

/// Create initialization vector
fn create_iv(
    hash_algorithm: &str,
    salt_value: &[u8],
    block_size: usize,
    block_key: &[u8],
) -> Result<Vec<u8>> {
    let mut iv = hash_data(hash_algorithm, &[salt_value, block_key])?;

    if iv.len() < block_size {
        iv.resize(block_size, 0x36);
    } else if iv.len() > block_size {
        iv.truncate(block_size);
    }

    Ok(iv)
}

/// Encrypt/decrypt data
fn crypt(
    encrypt: bool,
    cipher_algorithm: &str,
    cipher_chaining: &str,
    key: &[u8],
    iv: &[u8],
    input: &[u8],
) -> Result<Vec<u8>> {
    if cipher_chaining != "ChainingModeCBC" {
        return Err(OfficeCryptoError::UnsupportedAlgorithm(
            cipher_chaining.to_string(),
        ));
    }

    if cipher_algorithm.to_uppercase() != "AES" {
        return Err(OfficeCryptoError::UnsupportedAlgorithm(
            cipher_algorithm.to_string(),
        ));
    }

    if encrypt {
        let cipher = Aes256Cbc::new_from_slices(key, iv)
            .map_err(|e| OfficeCryptoError::Other(e.to_string()))?;
        Ok(cipher
            .encrypt_padded_vec_mut::<cipher::block_padding::NoPadding>(input))
    } else {
        let cipher = Aes256CbcDec::new_from_slices(key, iv)
            .map_err(|e| OfficeCryptoError::Other(e.to_string()))?;
        let mut output = input.to_vec();
        cipher
            .decrypt_padded_mut::<cipher::block_padding::NoPadding>(&mut output)
            .map_err(|e| OfficeCryptoError::Other(e.to_string()))?;
        Ok(output)
    }
}

/// Verify password
pub fn verify_password(password: &str, encryption_info: &AgileEncryptionInfo) -> Result<bool> {
    let verifier_hash_input_key = convert_password_to_key(
        password,
        &encryption_info.key.hash_algorithm,
        &encryption_info.key.salt_value,
        encryption_info.key.spin_count,
        encryption_info.key.key_bits,
        BlockKeys::VERIFIER_HASH_INPUT,
    )?;

    let verifier_hash_value_key = convert_password_to_key(
        password,
        &encryption_info.key.hash_algorithm,
        &encryption_info.key.salt_value,
        encryption_info.key.spin_count,
        encryption_info.key.key_bits,
        BlockKeys::VERIFIER_HASH_VALUE,
    )?;

    let verifier_hash_input = crypt(
        false,
        &encryption_info.key.cipher_algorithm,
        &encryption_info.key.cipher_chaining,
        &verifier_hash_input_key,
        &encryption_info.key.salt_value,
        &encryption_info.key.encrypted_verifier_hash_input,
    )?;

    let verifier_hash_value = crypt(
        false,
        &encryption_info.key.cipher_algorithm,
        &encryption_info.key.cipher_chaining,
        &verifier_hash_value_key,
        &encryption_info.key.salt_value,
        &encryption_info.key.encrypted_verifier_hash_value,
    )?;

    let actual_hash = hash_data(&encryption_info.key.hash_algorithm, &[&verifier_hash_input])?;

    let padded_actual_hash = if actual_hash.len() < verifier_hash_value.len() {
        let mut padded = actual_hash.clone();
        padded.resize(verifier_hash_value.len(), 0);
        padded
    } else {
        actual_hash
    };

    Ok(padded_actual_hash == verifier_hash_value)
}

/// Decrypt package
pub fn crypt_package(
    encrypt: bool,
    cipher_algorithm: &str,
    cipher_chaining: &str,
    hash_algorithm: &str,
    block_size: usize,
    salt_value: &[u8],
    key: &[u8],
    input: &[u8],
) -> Result<Vec<u8>> {
    let mut output_chunks = Vec::new();
    let offset = if encrypt { 0 } else { PACKAGE_OFFSET };

    let mut i = 0;
    let mut end = 0;

    while end < input.len() {
        let start = end;
        end = end.saturating_add(PACKAGE_ENCRYPTION_CHUNK_SIZE).min(input.len());

        let mut input_chunk = input[start + offset..end + offset].to_vec();

        // Pad chunk
        let remainder = input_chunk.len() % block_size;
        if remainder != 0 {
            input_chunk.resize(input_chunk.len() + block_size - remainder, 0);
        }

        // Create IV
        let block_key = create_u32le_buffer(i, 4);
        let iv = create_iv(hash_algorithm, salt_value, block_size, &block_key)?;

        // Crypt chunk
        let output_chunk = crypt(encrypt, cipher_algorithm, cipher_chaining, key, &iv, &input_chunk)?;
        output_chunks.push(output_chunk);

        i += 1;
    }

    let mut output = output_chunks.concat();

    if encrypt {
        // Prepend length
        let length_buffer = create_u32le_buffer(input.len() as u32, PACKAGE_OFFSET);
        output.splice(0..0, length_buffer);
    } else {
        // Truncate to size
        if input.len() >= 4 {
            let length = u32::from_le_bytes([input[0], input[1], input[2], input[3]]) as usize;
            output.truncate(length);
        }
    }

    Ok(output)
}

/// Decrypt with agile encryption
pub fn decrypt(
    encryption_info_buffer: &[u8],
    encrypted_package_buffer: &[u8],
    password: &str,
) -> Result<Vec<u8>> {
    // Parse encryption info
    let encryption_info = parse_encryption_info(encryption_info_buffer)?;

    // Verify password
    let valid = verify_password(password, &encryption_info)?;
    if !valid {
        return Err(OfficeCryptoError::InvalidPassword);
    }

    // Convert password to key
    let key = convert_password_to_key(
        password,
        &encryption_info.key.hash_algorithm,
        &encryption_info.key.salt_value,
        encryption_info.key.spin_count,
        encryption_info.key.key_bits,
        BlockKeys::KEY,
    )?;

    // Decrypt package key
    let package_key = crypt(
        false,
        &encryption_info.key.cipher_algorithm,
        &encryption_info.key.cipher_chaining,
        &key,
        &encryption_info.key.salt_value,
        &encryption_info.key.encrypted_key_value,
    )?;

    // Decrypt package
    let output = crypt_package(
        false,
        &encryption_info.package.cipher_algorithm,
        &encryption_info.package.cipher_chaining,
        &encryption_info.package.hash_algorithm,
        encryption_info.package.block_size,
        &encryption_info.package.salt_value,
        &package_key,
        encrypted_package_buffer,
    )?;

    // Validate ZIP
    if !is_valid_zip(&output) {
        return Err(OfficeCryptoError::InvalidPassword);
    }

    Ok(output)
}
