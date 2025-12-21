# AES File Encryptor (Rust)

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Rust](https://img.shields.io/badge/rust-stable-orange.svg)

**AES File Encryptor** is a high-performance, security-focused CLI tool designed for **atomicity**, **memory safety**, and **resistance to brute-force attacks**.

This project is a rewrite of my original [Python implementation](https://github.com/ShinuToki/aes-file-encryptor), optimized for speed and portable distribution.

The tool generates a lightweight binary named `locker` (or `locker.exe` on Windows) to handle all encryption tasks.

> [!WARNING]
> **Data Recovery Notice:** This tool uses industry-standard encryption with no backdoors. If you lose your password or the file's salt is corrupted, your data is **permanently irretrievable**. There is no "reset password" feature.

## Features

- **Authenticated Encryption:** Uses **AES-256-GCM** to ensure that data is not only private but also has not been tampered with.
- **Hardened Key Derivation:** Implements **Scrypt** with $N=2^{15}$ (memory-hard), making GPU-based brute-force attacks significantly more expensive.
- **Memory Hardening:** Leverages the `zeroize` crate to physically overwrite passwords and keys in RAM as soon as they are no longer needed.
- **Atomic File Writes:** Writes to a secure temporary file before renaming it to the target path. This prevents file corruption if the process is interrupted (e.g., power loss).
- **Library-First Design:** The core logic is decoupled from the CLI, allowing it to be used as a Rust crate in other projects.

## Installation

### Prerequisites

- [Rust & Cargo](https://rustup.rs/) (Stable)

### Build from Source

```bash
git clone https://github.com/ShinuToki/aes-file-encryptor-rs.git
cd aes-file-encryptor-rs
cargo build --release
```

The executable will be generated at `./target/release/locker` (Linux/macOS) or `.\target\release\locker.exe` (Windows).

#### Optional: Install to System Path

```bash
cargo install --path .
```

> [!NOTE]
> Ensure `~/.cargo/bin` is in your system's PATH.

## Usage

All commands are performed using the `locker` binary.

### Encrypt a File

By default, `locker` will prompt you securely for a password.

```bash
locker secrets.txt
```

- **Output:** `secrets.txt.enc`
- **Safety:** The original file is preserved. You should manually delete it after verifying the encrypted copy.

### Decrypt a File

```bash
locker secrets.txt.enc --decrypt
```

- **Output:** Restores the original filename (e.g., `secrets.txt`).

### Advanced Options

```bash
# Provide password via argument (Caution: visible in shell history)
locker data.zip -p "MyPassword"

# Specify a custom output path
locker data.zip -o encrypted_backup.enc

# Force overwrite of existing files without a prompt
locker data.zip.enc -d -f

# Combine options: decrypt with custom output, force overwrite
locker secrets.enc -d -o restored.txt -f
```

> [!TIP]
> Run `locker --help` to see all available options.

> [!CAUTION]
> Using `-p` exposes passwords in shell history and process lists. Prefer the interactive prompt for sensitive operations.

## Architecture

The project follows a **Library + Binary** structure to ensure the encryption engine is reusable and testable.

- **`src/lib.rs`**: The core `AESFileEncryptor` engine. Contains the cryptographic implementation and atomic write logic.
- **`src/main.rs`**: The CLI entry point. Handles argument parsing via `clap` and user interaction.

## Security Details

### Encrypted File Layout

When a file is encrypted, the resulting `.enc` file follows this binary structure:

| Offset (Bytes) | Field | Description |
| :--- | :--- | :--- |
| 0 - 15 | **Salt** | 128-bit random salt for KDF |
| 16 - 27 | **Nonce** | 96-bit random IV for AES-GCM |
| 28 - ... | **Ciphertext** | The encrypted data |
| Last 16 | **Tag** | GCM Authentication Tag |

### Cryptographic Stack

| Component | Algorithm | Configuration |
| :--- | :--- | :--- |
| **Cipher** | AES-256-GCM | Authenticated Encryption |
| **KDF** | Scrypt | $N=32768, r=8, p=1$ |
| **Salt** | CSPRNG | 16-byte random salt |
| **RAM Security** | `zeroize` | Secure memory wiping |

## Testing

To run the internal security and consistency tests:

```bash
cargo test
```

## License

This project is licensed under the **MIT License**.
