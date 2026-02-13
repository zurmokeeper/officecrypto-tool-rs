use officecrypto_tool::{decrypt, encrypt, is_encrypted, EncryptionType};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== OfficeCrypto Tool Rust Demo ===\n");

    // Example 1: Check if a file is encrypted
    println!("Example 1: Checking if file is encrypted");
    let test_data = b"PK\x03\x04"; // Simple ZIP header (not encrypted)
    match is_encrypted(test_data) {
        Ok(encrypted) => {
            if encrypted {
                println!("✓ File is encrypted");
            } else {
                println!("✓ File is not encrypted (or not a valid CFB file)");
            }
        }
        Err(e) => println!("✗ Error: {}", e),
    }

    println!("\nExample 2: Encrypt and decrypt demo");

    // Create a simple test file content (simulating an Office XML)
    let test_content = b"<?xml version=\"1.0\"?><workbook></workbook>";

    println!("Original content: {:?}", String::from_utf8_lossy(test_content));

    // Note: In real usage, you would encrypt an actual Office file
    // For demonstration, we'll show the API usage
    match encrypt(test_content, "password123", EncryptionType::Standard) {
        Ok(encrypted_data) => {
            println!("✓ Encryption successful! Size: {} bytes", encrypted_data.len());

            // Try to decrypt
            match decrypt(&encrypted_data, "password123") {
                Ok(decrypted_data) => {
                    println!("✓ Decryption successful!");
                    if decrypted_data == test_content {
                        println!("✓ Content matches original!");
                    } else {
                        println!("✗ Content doesn't match (expected for demo)");
                    }
                }
                Err(e) => println!("✗ Decryption error: {}", e),
            }

            // Try with wrong password
            match decrypt(&encrypted_data, "wrongpassword") {
                Ok(_) => println!("✗ Should have failed with wrong password"),
                Err(e) => println!("✓ Correctly rejected wrong password: {}", e),
            }
        }
        Err(e) => println!("✗ Encryption error: {}", e),
    }

    println!("\n=== Demo Complete ===");
    println!("\nUsage with real files:");
    println!("  let input = fs::read(\"encrypted.xlsx\")?;");
    println!("  let output = decrypt(&input, \"password123\")?;");
    println!("  fs::write(\"decrypted.xlsx\", output)?;");

    Ok(())
}
