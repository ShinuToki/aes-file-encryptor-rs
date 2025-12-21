use aes_file_encryptor_rs::AESFileEncryptor;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;

/// Helper: Sets up a temporary directory with a sample file for testing.
fn setup_env() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let file_path = temp_dir.path().join("secret.txt");
    let encrypted_path = temp_dir.path().join("secret.txt.enc");
    
    let mut file = File::create(&file_path).expect("Failed to create secret file");
    file.write_all(b"This is top secret content for testing purposes.")
        .expect("Failed to write to file");

    (temp_dir, file_path, encrypted_path)
}

#[test]
fn test_encrypt_and_decrypt_happy_path() {
    let (_dir, file_path, enc_path) = setup_env();
    let encryptor = AESFileEncryptor::new("StrongTestPassword123".to_string());

    // 1. Encrypt (force=true avoids prompt)
    encryptor.encrypt_file(&file_path, None, true).unwrap();
    assert!(enc_path.exists(), "The .enc file should have been created");

    // Delete original to prove we restore it from encryption
    fs::remove_file(&file_path).unwrap();
    assert!(!file_path.exists());
    
    // 2. Decrypt
    encryptor.decrypt_file(&enc_path, None, true).unwrap();
    assert!(file_path.exists(), "The original file should have been restored");
    
    let content = fs::read(&file_path).unwrap();
    assert_eq!(content, b"This is top secret content for testing purposes.");
}

#[test]
fn test_wrong_password_failure() {
    let (_dir, file_path, enc_path) = setup_env();
    
    // Encrypt with Password A
    let encryptor_a = AESFileEncryptor::new("PasswordA".to_string());
    encryptor_a.encrypt_file(&file_path, None, true).unwrap();

    // Try Decrypt with Password B
    let encryptor_b = AESFileEncryptor::new("PasswordB".to_string());
    let result = encryptor_b.decrypt_file(&enc_path, None, true);

    // Should fail (Integrity Check)
    assert!(result.is_err(), "Decryption should fail with wrong password");
}

#[test]
fn test_custom_configuration() {
    let (_dir, file_path, enc_path) = setup_env();
    let mut encryptor = AESFileEncryptor::new("ConfigTest".to_string());
    
    // We can modify config because we made it 'pub' in lib.rs
    encryptor.config.scrypt_n = 10; // Weaker/Faster parameters for testing
    
    encryptor.encrypt_file(&file_path, None, true).unwrap();
    
    // Verify file exists and has content (Salt + Nonce + Ciphertext)
    let metadata = fs::metadata(&enc_path).unwrap();
    assert!(metadata.len() > 28);
}