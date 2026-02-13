use officecrypto_tool::{decrypt, encrypt, is_encrypted, EncryptionType};

#[test]
fn test_basic_api() {
    // Test empty input
    let result = is_encrypted(&[]);
    assert!(result.is_ok());
    assert!(!result.unwrap());
}

#[test]
fn test_invalid_password() {
    let input = vec![1, 2, 3];
    let result = decrypt(&input, "");
    assert!(result.is_err());
}

#[test]
fn test_password_length() {
    let input = vec![1, 2, 3];
    let long_password = "a".repeat(256);
    let result = encrypt(&input, &long_password, EncryptionType::Standard);
    assert!(result.is_err());
}

// Note: Real file tests require test fixtures
// These would be added once we have sample encrypted files
