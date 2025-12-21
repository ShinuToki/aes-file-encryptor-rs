#![forbid(unsafe_code)]

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{anyhow, Context, Result};
use rand::{rng, RngCore};
use scrypt::{scrypt, Params};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::Path;
use tempfile::NamedTempFile;
use zeroize::Zeroizing;

/// Cryptographic parameters configuration.
/// Made 'pub' to allow modification in integration tests.
pub struct EncryptionConfig {
    pub scrypt_n: u32,    // CPU/Memory cost
    pub scrypt_r: u32,    // Block size
    pub scrypt_p: u32,    // Parallelization factor
    pub key_len: usize,   // 32 bytes for AES-256
    pub salt_len: usize,  // Randomness to prevent rainbow table attacks
    pub nonce_len: usize, // Initialization Vector for GCM mode
}

impl Default for EncryptionConfig {
    fn default() -> Self {
        Self {
            scrypt_n: 15, // 2^15 = 32768
            scrypt_r: 8,
            scrypt_p: 1,
            key_len: 32,
            salt_len: 16,
            nonce_len: 12, // Standard for AES-GCM
        }
    }
}

/// The main encryption engine.
pub struct AESFileEncryptor {
    /// The password is wrapped in `Zeroizing` to ensure it is wiped 
    /// from RAM once it is dropped (no longer in use).
    password: Zeroizing<String>,
    pub config: EncryptionConfig, // 'pub' for white-box testing
}

impl AESFileEncryptor {
    /// Creates a new encryptor instance with default configuration.
    pub fn new(password: String) -> Self {
        Self {
            password: Zeroizing::new(password),
            config: EncryptionConfig::default(),
        }
    }

    /// Derives a 256-bit key from the user's password using the Scrypt algorithm.
    fn derive_key(&self, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        let params = Params::new(
            self.config.scrypt_n as u8,
            self.config.scrypt_r,
            self.config.scrypt_p,
            self.config.key_len,
        ).map_err(|_| anyhow!("Invalid Scrypt parameters"))?;

        let mut key = [0u8; 32];
        scrypt(self.password.as_bytes(), salt, &params, &mut key)
            .map_err(|_| anyhow!("Key derivation failed"))?;
        
        Ok(Zeroizing::new(key))
    }

    /// Manual CLI prompt for file overwriting.
    fn confirm_overwrite(&self, path: &Path) -> bool {
        print!("File '{}' already exists. Overwrite? (y/n): ", path.display());
        io::stdout().flush().unwrap();
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        input.trim().to_lowercase() == "y"
    }

    /// Performs an Atomic Write:
    /// 1. Creates a temporary file in the same directory.
    /// 2. Writes all data blocks.
    /// 3. Replaces the target file with the temp file in one OS-level operation.
    ///
    /// This prevents file corruption if the program crashes or the power cuts.
    fn write_atomic(&self, target_path: &Path, data_blocks: Vec<&[u8]>, force: bool) -> Result<()> {
        if target_path.exists() && !force && !self.confirm_overwrite(target_path) {
            println!("Operation cancelled.");
            return Ok(());
        }

        let parent = target_path.parent().unwrap_or_else(|| Path::new("."));
        // Securely create a temp file in the parent dir of the target
        let mut tmp_file = NamedTempFile::new_in(parent)?;
        
        for block in data_blocks {
            tmp_file.write_all(block)?;
        }

        // The "Commit" phase: atomic rename
        tmp_file.persist(target_path).map_err(|e| anyhow!("Atomic write failed: {}", e))?;
        println!("Success: {}", target_path.display());
        Ok(())
    }

    /// Encrypts a file using AES-256-GCM.
    pub fn encrypt_file(&self, file_path: &Path, output_path: Option<&Path>, force: bool) -> Result<()> {
        println!("Reading '{}' into memory...", file_path.display());
        let plaintext = Zeroizing::new(fs::read(file_path).context("Failed to read input file")?);

        // Generate cryptographically secure random Salt and Nonce
        let mut salt = vec![0u8; self.config.salt_len];
        let mut nonce_bytes = vec![0u8; self.config.nonce_len];
        rng().fill_bytes(&mut salt);
        rng().fill_bytes(&mut nonce_bytes);

        // Derive key and initialize Cipher
        let key = self.derive_key(&salt)?;
        let cipher = Aes256Gcm::new_from_slice(&*key).map_err(|_| anyhow!("Cipher init failed"))?;
        
        // AES-GCM provides both Confidentiality and Authenticity (Integrity)
        println!("Encrypting data...");
        let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce_bytes), plaintext.as_ref())
            .map_err(|_| anyhow!("Encryption failed"))?;

        // Determine output path: use provided path or derive from input
        let out_path = match output_path {
            Some(p) => p.to_path_buf(),
            None => {
                let mut derived = file_path.to_path_buf();
                let ext = derived.extension().and_then(|e| e.to_str()).unwrap_or("");
                derived.set_extension(if ext.is_empty() { "enc".to_string() } else { format!("{}.enc", ext) });
                derived
            }
        };
        
        // Write Salt + Nonce + Ciphertext to the same file
        self.write_atomic(&out_path, vec![&salt, &nonce_bytes, &ciphertext], force)
    }

    /// Decrypts a file, verifying the password and integrity tag.
    pub fn decrypt_file(&self, file_path: &Path, output_path: Option<&Path>, force: bool) -> Result<()> {
        let mut file = File::open(file_path).context("Failed to open file")?;
        
        // Extract metadata header from the beginning of the file
        let mut salt = vec![0u8; self.config.salt_len];
        let mut nonce_bytes = vec![0u8; self.config.nonce_len];
        file.read_exact(&mut salt).context("Missing salt in header")?;
        file.read_exact(&mut nonce_bytes).context("Missing nonce in header")?;
        
        let mut ciphertext = Vec::new();
        file.read_to_end(&mut ciphertext)?;

        let key = self.derive_key(&salt)?;
        let cipher = Aes256Gcm::new_from_slice(&*key).map_err(|_| anyhow!("Cipher init failed"))?;

        println!("Decrypting and verifying integrity...");
        let plaintext = cipher.decrypt(Nonce::from_slice(&nonce_bytes), ciphertext.as_ref())
            .map_err(|_| anyhow!("Authentication failed: Incorrect password or corrupted file"))?;

        // Determine output path: use provided path or derive from input
        let out_path = match output_path {
            Some(p) => p.to_path_buf(),
            None => {
                let mut derived = file_path.to_path_buf();
                if derived.extension().is_some_and(|ext| ext == "enc") {
                    derived.set_extension("");
                } else {
                    derived.set_extension("dec");
                }
                derived
            }
        };
        
        self.write_atomic(&out_path, vec![&plaintext], force)
    }
}