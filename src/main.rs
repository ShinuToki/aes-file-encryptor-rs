use anyhow::{anyhow, Result};
use clap::Parser;
use std::path::PathBuf;
// Import the public struct from our library
use aes_file_encryptor_rs::AESFileEncryptor;

/// Command-line arguments configuration using `clap`.
/// This automatically generates help menus (-h) and version info (-V).
#[derive(Parser, Debug)]
#[command(version, about = "AES-GCM File Encryption Tool")]
struct Args {
    /// Path to the target file
    file: PathBuf,

    /// Optional password. If omitted, the program will prompt securely.
    #[arg(short, long)]
    password: Option<String>,

    /// Enable decryption mode (default is encryption)
    #[arg(short, long)]
    decrypt: bool,

    /// Overwrite existing files without asking for confirmation
    #[arg(short, long)]
    force: bool,

    /// Custom output path (optional, otherwise auto-derived)
    #[arg(short, long)]
    output: Option<PathBuf>,
}

fn main() -> Result<()> {
    // Parse CLI arguments
    let args = Args::parse();

    // Securely prompt for password if not provided in arguments
    let password = match args.password {
        Some(p) => p,
        None => rpassword::prompt_password("Enter password: ")?,
    };

    if password.is_empty() {
        return Err(anyhow!("Password cannot be empty."));
    }

    let encryptor = AESFileEncryptor::new(password);

    // Execute requested operation
    if args.decrypt {
        encryptor.decrypt_file(&args.file, args.output.as_deref(), args.force)?;
    } else {
        encryptor.encrypt_file(&args.file, args.output.as_deref(), args.force)?;
    }

    Ok(())
}