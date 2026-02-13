use crate::error::{OfficeCryptoError, Result};
use md5::{Digest, Md5};

// Simple RC4 implementation to avoid type issues
struct Rc4State {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4State {
    fn new(key: &[u8]) -> Self {
        let mut s = [0u8; 256];
        for (i, item) in s.iter_mut().enumerate() {
            *item = i as u8;
        }

        let mut j = 0u8;
        for i in 0..256 {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
            s.swap(i, j as usize);
        }

        Rc4State { s, i: 0, j: 0 }
    }

    fn process(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.s[self.i as usize]);
            self.s.swap(self.i as usize, self.j as usize);
            let k = self.s[(self.s[self.i as usize].wrapping_add(self.s[self.j as usize])) as usize];
            *byte ^= k;
        }
    }
}

/// Convert password to RC4 encryption key
pub fn convert_password_to_key(password: &str, salt: &[u8], block: u32) -> Result<Vec<u8>> {
    // Convert password to UTF-16LE
    let password_buf: Vec<u8> = password
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();

    // Initial hash: MD5(password)
    let mut hasher = Md5::new();
    hasher.update(&password_buf);
    let h0 = hasher.finalize();

    // Truncate to 5 bytes
    let mut truncated_hash = h0[..5].to_vec();

    // Concatenate with salt and repeat 16 times
    let mut intermediate_buffer = Vec::new();
    truncated_hash.extend_from_slice(salt);
    for _ in 0..16 {
        intermediate_buffer.extend_from_slice(&truncated_hash);
        intermediate_buffer.extend_from_slice(salt);
    }

    // Hash the intermediate buffer
    let mut hasher = Md5::new();
    hasher.update(&intermediate_buffer);
    let intermediate_hash = hasher.finalize();

    // Truncate to 5 bytes again
    truncated_hash = intermediate_hash[..5].to_vec();

    // Append block number
    let block_bytes = block.to_le_bytes();
    truncated_hash.extend_from_slice(&block_bytes);

    // Final hash
    let mut hasher = Md5::new();
    hasher.update(&truncated_hash);
    let h_final = hasher.finalize();

    // Key is first 128 bits (16 bytes)
    let key = h_final[..16].to_vec();

    Ok(key)
}

/// Verify password using encrypted verifier
pub fn verify_password(
    password: &str,
    salt: &[u8],
    encrypted_verifier: &[u8],
    encrypted_verifier_hash: &[u8],
) -> Result<bool> {
    let block = 0;
    let key = convert_password_to_key(password, salt, block)?;

    // Decrypt verifier
    let mut cipher = Rc4State::new(&key);
    let mut verifier = encrypted_verifier.to_vec();
    cipher.process(&mut verifier);

    // Hash verifier
    let mut hasher = Md5::new();
    hasher.update(&verifier);
    let hash = hasher.finalize();

    // Decrypt verifier hash (need fresh cipher state)
    let mut cipher = Rc4State::new(&key);
    // Skip the verifier bytes to get to correct position in keystream
    let mut dummy = vec![0u8; encrypted_verifier.len()];
    cipher.process(&mut dummy);

    let mut verifier_hash = encrypted_verifier_hash.to_vec();
    cipher.process(&mut verifier_hash);

    // Compare hashes
    Ok(&hash[..] == &verifier_hash[..16])
}

/// Decrypt data using RC4
pub fn decrypt(password: &str, salt: &[u8], input: &[u8], block_size: usize) -> Result<Vec<u8>> {
    let mut output_chunks = Vec::new();
    let mut block = 0u32;
    let mut start = 0;

    while start < input.len() {
        let end = (start + block_size).min(input.len());
        let mut input_chunk = input[start..end].to_vec();

        // Get key for this block
        let key = convert_password_to_key(password, salt, block)?;

        // Decrypt chunk
        let mut cipher = Rc4State::new(&key);
        cipher.process(&mut input_chunk);

        output_chunks.push(input_chunk);
        block += 1;
        start = end;
    }

    Ok(output_chunks.concat())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_convert_password_to_key() {
        let password = "password";
        let salt = vec![0u8; 16];
        let key = convert_password_to_key(password, &salt, 0).unwrap();
        assert_eq!(key.len(), 16);
    }
}
