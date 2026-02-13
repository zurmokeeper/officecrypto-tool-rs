use crate::error::{OfficeCryptoError, Result};
use crate::util::{create_u32le_buffer, xor_bytes};
use aes::cipher::generic_array::GenericArray;
use aes::Aes128;
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyInit};
use ecb::{Decryptor, Encryptor};
use sha1::{Digest, Sha1};
use std::io::Write;

const ITER_COUNT: usize = 50000;
const PACKAGE_OFFSET: usize = 8;
const BLOCK_SIZE: usize = 16;
const CHUNK_SIZE: usize = 4096;

/// Convert password to encryption key using ECMA-376 Standard algorithm
pub fn convert_password_to_key(
    password: &str,
    _alg_id: u32,
    _alg_id_hash: u32,
    _provider_type: u32,
    key_size: u32,
    _salt_size: usize,
    salt: &[u8],
) -> Result<Vec<u8>> {
    let cb_required_key_length = (key_size / 8) as usize;

    // Convert password to UTF-16LE
    let password_buf: Vec<u8> = password
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();

    // Initial hash: SHA1(salt + password)
    let mut hasher = Sha1::new();
    hasher.update(salt);
    hasher.update(&password_buf);
    let mut salted_password_hash = hasher.finalize().to_vec();

    // Iterate ITER_COUNT times
    for i in 0..ITER_COUNT {
        let i_bytes = (i as u32).to_le_bytes();
        let mut hasher = Sha1::new();
        hasher.update(&i_bytes);
        hasher.update(&salted_password_hash);
        salted_password_hash = hasher.finalize().to_vec();
    }

    // Final hash
    let block = [0u8; 4];
    let mut hasher = Sha1::new();
    hasher.update(&salted_password_hash);
    hasher.update(&block);
    let h_final = hasher.finalize();

    let cb_hash = 20;

    // Generate X1
    let mut buf1 = vec![0x36u8; 64];
    let xored = xor_bytes(&h_final[..cb_hash], &buf1[..cb_hash]);
    buf1[..cb_hash].copy_from_slice(&xored);

    let mut hasher = Sha1::new();
    hasher.update(&buf1);
    let x1 = hasher.finalize();

    // Generate X2
    let mut buf2 = vec![0x5Cu8; 64];
    let xored = xor_bytes(&h_final[..cb_hash], &buf2[..cb_hash]);
    buf2[..cb_hash].copy_from_slice(&xored);

    let mut hasher = Sha1::new();
    hasher.update(&buf2);
    let x2 = hasher.finalize();

    // Combine X1 and X2
    let mut x3 = Vec::with_capacity(40);
    x3.extend_from_slice(&x1);
    x3.extend_from_slice(&x2);

    // Derive key
    let key_derived = x3[..cb_required_key_length].to_vec();

    Ok(key_derived)
}

/// Verify password with encrypted verifier
pub fn verify_key(
    key: &[u8],
    encrypted_verifier: &[u8],
    encrypted_verifier_hash: &[u8],
) -> Result<bool> {
    // Decrypt verifier
    let mut cipher = Decryptor::<Aes128>::new_from_slice(key)
        .map_err(|e| OfficeCryptoError::Other(e.to_string()))?;

    let mut verifier = encrypted_verifier.to_vec();
    for chunk in verifier.chunks_exact_mut(BLOCK_SIZE) {
        let block = GenericArray::from_mut_slice(chunk);
        cipher.decrypt_block_mut(block);
    }

    // Hash the decrypted verifier
    let mut hasher = Sha1::new();
    hasher.update(&verifier);
    let expected_hash = hasher.finalize();

    // Decrypt verifier hash
    let mut verifier_hash = encrypted_verifier_hash.to_vec();
    for chunk in verifier_hash.chunks_exact_mut(BLOCK_SIZE) {
        let block = GenericArray::from_mut_slice(chunk);
        cipher.decrypt_block_mut(block);
    }

    // Compare first 20 bytes
    Ok(&expected_hash[..] == &verifier_hash[..20])
}

/// Decrypt encrypted package using ECMA-376 Standard
pub fn decrypt(key: &[u8], input: &[u8]) -> Result<Vec<u8>> {
    if input.len() < PACKAGE_OFFSET {
        return Err(OfficeCryptoError::InvalidInput);
    }

    let mut cipher = Decryptor::<Aes128>::new_from_slice(key)
        .map_err(|e| OfficeCryptoError::Other(e.to_string()))?;

    let mut output_chunks = Vec::new();
    let mut end = 0;

    while end < input.len() - PACKAGE_OFFSET {
        let start = end;
        end = (start + CHUNK_SIZE).min(input.len() - PACKAGE_OFFSET);

        // Get chunk
        let mut input_chunk = input[start + PACKAGE_OFFSET..end + PACKAGE_OFFSET].to_vec();

        // Pad if needed
        let remainder = input_chunk.len() % BLOCK_SIZE;
        if remainder != 0 {
            input_chunk.resize(input_chunk.len() + BLOCK_SIZE - remainder, 0);
        }

        // Decrypt chunk block by block
        for chunk in input_chunk.chunks_exact_mut(BLOCK_SIZE) {
            let block = GenericArray::from_mut_slice(chunk);
            cipher.decrypt_block_mut(block);
        }

        output_chunks.push(input_chunk);
    }

    let mut output = output_chunks.concat();

    // Truncate to actual size
    if input.len() >= 4 {
        let length = u32::from_le_bytes([input[0], input[1], input[2], input[3]]) as usize;
        if length <= output.len() {
            output.truncate(length);
        }
    }

    Ok(output)
}

/// Encrypt package using ECMA-376 Standard
pub fn encrypt(key: &[u8], input: &[u8]) -> Result<Vec<u8>> {
    let mut cipher = Encryptor::<Aes128>::new_from_slice(key)
        .map_err(|e| OfficeCryptoError::Other(e.to_string()))?;

    let mut output_chunks = Vec::new();
    let mut end = 0;

    while end < input.len() {
        let start = end;
        end = (start + CHUNK_SIZE).min(input.len());

        // Get chunk
        let mut input_chunk = input[start..end].to_vec();

        // Pad if needed
        let remainder = input_chunk.len() % BLOCK_SIZE;
        if remainder != 0 {
            input_chunk.resize(input_chunk.len() + BLOCK_SIZE - remainder, 0);
        }

        // Encrypt chunk block by block
        for chunk in input_chunk.chunks_exact_mut(BLOCK_SIZE) {
            let block = GenericArray::from_mut_slice(chunk);
            cipher.encrypt_block_mut(block);
        }

        output_chunks.push(input_chunk);
    }

    let mut output = output_chunks.concat();

    // Prepend length
    let length_buffer = create_u32le_buffer(input.len() as u32, PACKAGE_OFFSET);
    output.splice(0..0, length_buffer);

    Ok(output)
}

/// Generate encrypted verifier for encryption
pub fn gen_verifier(key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    use rand::Rng;
    let mut rng = rand::thread_rng();

    // Generate random verifier input
    let verifier_hash_input: Vec<u8> = (0..16).map(|_| rng.gen()).collect();

    let mut cipher = Encryptor::<Aes128>::new_from_slice(key)
        .map_err(|e| OfficeCryptoError::Other(e.to_string()))?;

    // Encrypt verifier input
    let mut verifier_hash_input_value = verifier_hash_input.clone();
    for chunk in verifier_hash_input_value.chunks_exact_mut(BLOCK_SIZE) {
        let block = GenericArray::from_mut_slice(chunk);
        cipher.encrypt_block_mut(block);
    }

    // Hash verifier input
    let mut hasher = Sha1::new();
    hasher.update(&verifier_hash_input);
    let mut verifier_hash_input_key = hasher.finalize().to_vec();

    // Pad hash
    let remainder = verifier_hash_input_key.len() % BLOCK_SIZE;
    if remainder != 0 {
        verifier_hash_input_key.resize(verifier_hash_input_key.len() + BLOCK_SIZE - remainder, 0);
    }

    // Encrypt hash
    for chunk in verifier_hash_input_key.chunks_exact_mut(BLOCK_SIZE) {
        let block = GenericArray::from_mut_slice(chunk);
        cipher.encrypt_block_mut(block);
    }

    Ok((verifier_hash_input_value, verifier_hash_input_key))
}

/// Build complete encryption info structure
pub fn build_encryption_info(key: &[u8], key_data_salt_value: &[u8]) -> Result<Vec<u8>> {
    let mut blob = vec![0u8; 224];
    let mut pos = 0;

    // Version
    blob[pos..pos + 2].copy_from_slice(&0x0004u16.to_le_bytes());
    pos += 2;
    blob[pos..pos + 2].copy_from_slice(&0x0002u16.to_le_bytes());
    pos += 2;

    // Flags
    blob[pos..pos + 4].copy_from_slice(&0x24u32.to_le_bytes());
    pos += 4;

    // Header size
    blob[pos..pos + 4].copy_from_slice(&0x8Cu32.to_le_bytes());
    pos += 4;

    // Flags
    blob[pos..pos + 4].copy_from_slice(&0x24u32.to_le_bytes());
    pos += 4;

    // SizeExtra
    blob[pos..pos + 4].copy_from_slice(&0x00u32.to_le_bytes());
    pos += 4;

    // AlgID (AES-128)
    blob[pos..pos + 4].copy_from_slice(&0x660Eu32.to_le_bytes());
    pos += 4;

    // AlgIDHash (SHA1)
    blob[pos..pos + 4].copy_from_slice(&0x8004u32.to_le_bytes());
    pos += 4;

    // KeySize
    blob[pos..pos + 4].copy_from_slice(&0x80u32.to_le_bytes());
    pos += 4;

    // ProviderType
    blob[pos..pos + 4].copy_from_slice(&0x18u32.to_le_bytes());
    pos += 4;

    // Reserved
    blob[pos..pos + 8].fill(0);
    pos += 8;

    // Provider name (UTF-16LE)
    let provider_name = "Microsoft Enhanced RSA and AES Cryptographic Provider (Prototype)";
    let provider_name_utf16: Vec<u8> = provider_name
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let name_len = provider_name_utf16.len().min(108);
    blob[pos..pos + name_len].copy_from_slice(&provider_name_utf16[..name_len]);
    pos += 108; // 54 characters * 2 bytes

    // Salt size
    blob[pos..pos + 4].copy_from_slice(&0x10u32.to_le_bytes());
    pos += 4;

    // Generate verifier
    let (encrypted_verifier, encrypted_verifier_hash) = gen_verifier(key)?;

    // Salt
    blob[pos..pos + 16].copy_from_slice(key_data_salt_value);
    pos += 16;

    // Encrypted verifier
    blob[pos..pos + 16].copy_from_slice(&encrypted_verifier);
    pos += 16;

    // Verifier hash size
    blob[pos..pos + 4].copy_from_slice(&0x14u32.to_le_bytes());
    pos += 4;

    // Encrypted verifier hash
    blob[pos..pos + 32].copy_from_slice(&encrypted_verifier_hash);

    Ok(blob)
}

/// Encrypt standard format (full process)
pub fn encrypt_standard(input: &[u8], password: &str) -> Result<Vec<u8>> {
    use rand::Rng;
    let mut rng = rand::thread_rng();

    let key_size = 128;
    let alg_id = 0x660E;
    let alg_id_hash = 0x8004;
    let provider_type = 0x18;
    let salt_size = 16;

    // Generate random salt
    let key_data_salt_value: Vec<u8> = (0..16).map(|_| rng.gen()).collect();

    // Derive key from password
    let key = convert_password_to_key(
        password,
        alg_id,
        alg_id_hash,
        provider_type,
        key_size,
        salt_size,
        &key_data_salt_value,
    )?;

    // Build encryption info
    let encryption_info_buffer = build_encryption_info(&key, &key_data_salt_value)?;

    // Encrypt package
    let encrypted_package = encrypt(&key, input)?;

    // Create CFB with cursor
    use std::io::Cursor;
    let cursor = Cursor::new(Vec::new());
    let mut comp = cfb::CompoundFile::create_with_version(cfb::Version::V3, cursor)
        .map_err(|e| OfficeCryptoError::CfbError(e.to_string()))?;

    // Add encryption info
    {
        let mut stream = comp.create_stream("/EncryptionInfo")
            .map_err(|e| OfficeCryptoError::CfbError(e.to_string()))?;
        stream.write_all(&encryption_info_buffer)?;
    }

    // Add encrypted package
    {
        let mut stream = comp.create_stream("/EncryptedPackage")
            .map_err(|e| OfficeCryptoError::CfbError(e.to_string()))?;
        stream.write_all(&encrypted_package)?;
    }

    // Get buffer
    let output = comp.into_inner().into_inner();

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_convert_password_to_key() {
        let password = "123456";
        let salt = vec![0x91, 0x33, 0xca, 0x74, 0x07, 0xdd, 0x5a, 0x2d,
                       0x04, 0x55, 0x34, 0x91, 0x79, 0xe3, 0x2a, 0xe9];
        let key = convert_password_to_key(password, 0x660E, 0x8004, 0x18, 128, 16, &salt).unwrap();
        assert_eq!(key.len(), 16);
    }
}
