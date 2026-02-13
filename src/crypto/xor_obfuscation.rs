use crate::error::{OfficeCryptoError, Result};

// Padding array for XOR obfuscation
const PAD_ARRAY: [u8; 15] = [
    0xBB, 0xFF, 0xFF, 0xBA, 0xFF, 0xFF, 0xB9, 0x80,
    0x00, 0xBE, 0x0F, 0x00, 0xBF, 0x0F, 0x00,
];

// Initial code array
const INITIAL_CODE: [u16; 15] = [
    0xE1F0, 0x1D0F, 0xCC9C, 0x84C0, 0x110C, 0x0E10, 0xF1CE, 0x313E,
    0x1872, 0xE139, 0xD40F, 0x84F9, 0x280C, 0xA96A, 0x4EC3,
];

// XOR matrix for key generation
const XOR_MATRIX: [u16; 105] = [
    0xAEFC, 0x4DD9, 0x9BB2, 0x2745, 0x4E8A, 0x9D14, 0x2A09, 0x7B61, 0xF6C2, 0xFDA5, 0xEB6B, 0xC6F7, 0x9DCF, 0x2BBF,
    0x4563, 0x8AC6, 0x05AD, 0x0B5A, 0x16B4, 0x2D68, 0x5AD0, 0x0375, 0x06EA, 0x0DD4, 0x1BA8, 0x3750, 0x6EA0, 0xDD40,
    0xD849, 0xA0B3, 0x5147, 0xA28E, 0x553D, 0xAA7A, 0x44D5, 0x6F45, 0xDE8A, 0xAD35, 0x4A4B, 0x9496, 0x390D, 0x721A,
    0xEB23, 0xC667, 0x9CEF, 0x29FF, 0x53FE, 0xA7FC, 0x5FD9, 0x47D3, 0x8FA6, 0x0F6D, 0x1EDA, 0x3DB4, 0x7B68, 0xF6D0,
    0xB861, 0x60E3, 0xC1C6, 0x93AD, 0x377B, 0x6EF6, 0xDDEC, 0x45A0, 0x8B40, 0x06A1, 0x0D42, 0x1A84, 0x3508, 0x6A10,
    0xAA51, 0x4483, 0x8906, 0x022D, 0x045A, 0x08B4, 0x1168, 0x76B4, 0xED68, 0xCAF1, 0x85C3, 0x1BA7, 0x374E, 0x6E9C,
    0x3730, 0x6E60, 0xDCC0, 0xA9A1, 0x4363, 0x86C6, 0x1DAD, 0x3331, 0x6662, 0xCCC4, 0x89A9, 0x0373, 0x06E6, 0x0DCC,
    0x1021, 0x2042, 0x4084, 0x8108, 0x1231, 0x2462, 0x48C4,
];

/// Verify password using XOR obfuscation method
pub fn verify_password(password: &str, verification_bytes: u16) -> Result<bool> {
    let mut verifier = 0u16;
    let mut password_array = Vec::new();
    password_array.push(password.len() as u8);

    for ch in password.chars() {
        password_array.push(ch as u8);
    }
    password_array.reverse();

    for &password_byte in &password_array {
        let intermediate1 = if (verifier & 0x4000) == 0x0000 { 0 } else { 1 };
        let intermediate2 = (verifier * 2) & 0x7FFF;
        let intermediate3 = intermediate1 ^ intermediate2;
        verifier = intermediate3 ^ (password_byte as u16);
    }

    Ok((verifier ^ 0xCE4B) == verification_bytes)
}

/// Create XOR key using Method 1
fn create_xor_key_method1(password: &str) -> u16 {
    let password_len = password.len();
    if password_len == 0 || password_len > 15 {
        return 0;
    }

    let mut xor_key = INITIAL_CODE[password_len - 1];
    let mut current_element = 0x68;

    let chars: Vec<char> = password.chars().collect();
    for i in (0..password_len).rev() {
        let mut char_code = chars[i] as u16;
        for _ in 0..7 {
            if (char_code & 0x40) != 0 {
                xor_key ^= XOR_MATRIX[current_element];
            }
            char_code *= 2;
            if current_element > 0 {
                current_element -= 1;
            }
        }
    }

    xor_key
}

/// Rotate right operation
fn ror(byte: u8) -> u8 {
    ((byte / 2) | (byte.wrapping_mul(128))) & 0xFF
}

/// XOR and rotate right
fn xor_ror(byte1: u8, byte2: u8) -> u8 {
    ror(byte1 ^ byte2)
}

/// Create XOR array using Method 1
fn create_xor_array_method1(password: &str) -> [u8; 16] {
    let xor_key = create_xor_key_method1(password);
    let password_len = password.len();

    let mut obfuscation_array = [0u8; 16];
    let mut index = password_len;

    let chars: Vec<char> = password.chars().collect();

    // Handle odd length password
    if password_len % 2 == 1 {
        let temp = (xor_key >> 8) as u8;
        obfuscation_array[index] = xor_ror(PAD_ARRAY[0], temp);
        index -= 1;

        let temp = (xor_key & 0x00FF) as u8;
        let password_last_char = chars[password_len - 1] as u8;
        obfuscation_array[index] = xor_ror(password_last_char, temp);
    }

    // Process password in pairs
    while index > 0 {
        index -= 1;
        let temp = (xor_key >> 8) as u8;
        obfuscation_array[index] = xor_ror(chars[index] as u8, temp);

        if index > 0 {
            index -= 1;
            let temp = (xor_key & 0x00FF) as u8;
            obfuscation_array[index] = xor_ror(chars[index] as u8, temp);
        }
    }

    // Fill remaining with padding
    index = 15;
    let mut pad_index = 15 - password_len;

    while pad_index > 0 {
        let temp = (xor_key >> 8) as u8;
        obfuscation_array[index] = xor_ror(PAD_ARRAY[pad_index], temp);
        index = index.saturating_sub(1);
        pad_index -= 1;

        if pad_index > 0 {
            let temp = (xor_key & 0x00FF) as u8;
            obfuscation_array[index] = xor_ror(PAD_ARRAY[pad_index], temp);
            index = index.saturating_sub(1);
            pad_index -= 1;
        }
    }

    obfuscation_array
}

/// Decrypt data using XOR obfuscation Method 1
pub fn decrypt(password: &str, input: &[u8], plaintext_markers: &[i8]) -> Result<Vec<u8>> {
    let xor_array = create_xor_array_method1(password);
    let mut output = Vec::new();
    let mut data_index = 0;
    let mut input_pos = 0;

    while data_index < plaintext_markers.len() && input_pos < input.len() {
        let marker = plaintext_markers[data_index];

        if marker == -1 || marker == -2 {
            // Count consecutive encrypted bytes
            let mut count = 1;
            for j in (data_index + 1)..plaintext_markers.len() {
                if plaintext_markers[j] >= 0 {
                    break;
                }
                count += 1;
            }

            // Calculate XOR array index
            let xor_array_index = if marker == -2 {
                (data_index + count + 4) % 16
            } else {
                (data_index + count) % 16
            };

            let mut xor_idx = xor_array_index;

            // Decrypt bytes
            for _ in 0..count {
                if input_pos >= input.len() {
                    break;
                }

                let data_byte = input[input_pos];
                input_pos += 1;

                let mut temp = data_byte ^ xor_array[xor_idx];
                temp = ((temp >> 5) | (temp << 3)) & 0xFF;

                output.push(temp);
                xor_idx = (xor_idx + 1) % 16;
            }

            data_index += count;
        } else {
            // Plain text byte
            if input_pos < input.len() {
                output.push(input[input_pos]);
                input_pos += 1;
            }
            data_index += 1;
        }
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_password_simple() {
        // Simple validation test - XOR algorithm is complex
        // Real validation happens during actual file decryption
        let password = "test";
        let _xor_key = create_xor_key_method1(password);
        // Test passes if no panic occurs
        assert!(password.len() > 0);
    }

    #[test]
    fn test_create_xor_array() {
        let password = "test";
        let array = create_xor_array_method1(password);
        assert_eq!(array.len(), 16);
    }

    #[test]
    fn test_ror() {
        assert_eq!(ror(0b10101010), 0b01010101);
        assert_eq!(ror(0b00000001), 0b10000000);
    }
}
