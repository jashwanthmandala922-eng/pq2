# PQ-VAULT Technical Specification

## Cross-Platform Post-Quantum Password Manager

**Version 2.0**  
**Last Updated: April 2026**

---

## 1. Executive Summary

**PQ-Vault** is a production-ready, cross-platform password manager implementing NIST-approved post-quantum cryptographic algorithms. The system combines hybrid key encapsulation (X25519 + ML-KEM), Argon2id key derivation, and multi-factor authentication to provide defense-in-depth security against both classical and quantum threats.

### Core Security Properties
- **Hybrid KEM**: Combines X25519 (classical) with ML-KEM-768 (post-quantum) via HKDF
- **Memory-Hard KDF**: Argon2id with m=65536, t=3, p=4
- **Multi-Factor Auth**: Master Password + TOTP / Passkey / Biometric
- **Zero-Knowledge**: All sensitive data encrypted with ML-KEM/ChaCha20
- **Local-Only**: No cloud dependencies, all computations performed locally

---

## 2. Cryptographic Architecture

### 2.1 Hybrid Key Encapsulation Mechanism (Hybrid KEM)

Combines classical and post-quantum security for defense-in-depth:

```
┌─────────────────────────────────────────────────────────────┐
│                    HYBRID KEM PROTOCOL                       │
├─────────────────────────────────────────────────────────────┤
│  Sender                                                      │
│  ┌──────────────┐    ┌──────────────┐                       │
│  │ X25519       │    │ ML-KEM-768   │                       │
│  │ KeyGen()     │    │ KeyGen()     │                       │
│  └──────┬───────┘    └──────┬───────┘                       │
│         │                   │                                │
│         ▼                   ▼                                │
│  ┌──────────────┐    ┌──────────────┐                       │
│  │ Ephermeral   │    │ Kyber        │                       │
│  │ Public Key   │    │ Ciphertext   │                       │
│  └──────┬───────┘    └──────┬───────┘                       │
│         │                   │                                │
│         └─────────┬─────────┘                                │
│                   ▼                                          │
│          ┌────────────────┐                                 │
│          │ HKDF-SHA3-256  │                                 │
│          │ (64B → 32B)     │                                 │
│          └────────┬────────┘                                 │
│                   ▼                                          │
│          ┌────────────────┐                                 │
│          │  Shared Secret │                                 │
│          │  (32 bytes)    │                                 │
│          └────────────────┘                                 │
└─────────────────────────────────────────────────────────────┘
```

#### X25519 (Classical)
- **Key Size**: 32 bytes
- **Implementation**: Pure Rust Montgomery curve scalar multiplication
- **Base Point**: 9 (RFC 7748)

#### ML-KEM-768 (Post-Quantum)
- **Public Key**: 1184 bytes
- **Secret Key**: 2400 bytes
- **Ciphertext**: 1088 bytes
- **Security Level**: NIST Level 3 (128-bit)
- **Implementation**: Pure Rust with NTT polynomial operations

#### HKDF-SHA3-256
- **Input**: 64 bytes (32B classical + 32B quantum)
- **Output**: 32 bytes
- **Info String**: "SecureVault-HKDF-v1"

### 2.2 Key Derivation (Argon2id)

Resistance against GPU/ASIC brute-force attacks:

| Parameter | Value | Purpose |
|-----------|-------|---------|
| Memory (m) | 65536 KiB | 64MB memory-hard |
| Iterations (t) | 3 | Computational cost |
| Parallelism (p) | 4 | Parallel processing |
| Salt Size | 32 bytes | Unique per vault |
| Output | 32 bytes | Master key |

**Salt Storage**: First 32 bytes of vault binary format

```rust
// Binary Vault Format
┌────────┬────────────┬──────────────────┐
│ Salt   │ ML-KEM     │ Encrypted        │
│ (32B)  │ Ciphertext │ Vault Data       │
│        │ (1088B)    │                  │
└────────┴────────────┴──────────────────┘
```

### 2.3 Post-Quantum Algorithms

| Algorithm | Purpose | Status |
|-----------|---------|--------|
| **ML-KEM-768** | Key Encapsulation | Implemented (Rust) |
| **ML-DSA-65** | Digital Signatures | Stub (requires full polynomial math) |
| **SPHINCS+** | Hash-based Signatures | Stub |
| **SHA3-256** | Hashing | Implemented |
| **ChaCha20** | CSPRNG | Implemented |

### 2.4 Encryption Flow

```
Master Password
      │
      ▼
┌──────────────┐
│  Argon2id    │  m=65536, t=3, p=4
│  KDF         │  + 32B Salt
└──────┬───────┘
       │
       ▼
┌────────────────┐
│ Master Key     │
│ (64 bytes)     │
└──────┬─────────┘
       │
       ├────────────────────┐
       ▼                    ▼
┌──────────────┐    ┌──────────────┐
│ ML-KEM      │    │ X25519       │
│ Encapsulate │    │ KeyGen       │
└──────┬───────┘    └──────┬───────┘
       │                   │
       └─────────┬─────────┘
                 ▼
          ┌──────────┐
          │ HKDF     │  Derived key for ChaCha20
          └────┬─────┘
               │
               ▼
        ┌────────────┐
        │ ChaCha20   │  AEAD encryption
        │ + SHA3-Auth│
        └────────────┘
```

---

## 3. Multi-Layer Authentication System

### 3.1 Authentication Methods

| Method | Factor | Use Case |
|--------|--------|----------|
| Master Password | Knowledge | Primary auth |
| TOTP | Knowledge + Token | 2FA |
| Passkey | Possession | Passwordless |
| Biometric | Inherence | Quick unlock |

### 3.2 Login State Machine

```
                         ┌─────────────┐
                         │   INITIAL  │
                         └──────┬──────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        │                       │                       │
        ▼                       ▼                       ▼
┌───────────────┐    ┌───────────────┐    ┌───────────────┐
│   PASSWORD    │    │   PASSKEY     │    │  BIOMETRIC    │
│   Input       │    │   Challenge   │    │   Prompt      │
└───────┬───────┘    └───────┬───────┘    └───────┬───────┘
        │                     │                     │
        ▼                     │                     │
┌───────────────┐             │                     │
│   Argon2id    │             │                     │
│   Verify      │             │                     │
└───────┬───────┘             │                     │
        │                     │                     │
        ├──────────┐          │                     │
        ▼          ▼          │                     │
┌───────────┐ ┌───────────┐   │                     │
│ TOTP      │ │ AUTHENTI-│   │                     │
│ Required? │ │ CATED     │◄──┘                    │
└─────┬─────┘ └───────────┘ (if passkey valid)     │
      │ (YES)                                       │
      ▼                                             │
┌───────────────┐                                   │
│   TOTP        │                                   │
│   Verify      │                                   │
│   Window ±1   │                                   │
└───────┬───────┘                                   │
        │                                           │
        └───────────────────────┬─────────────────┘
                                │
                                ▼
                       ┌───────────────┐
                       │  AUTHENTICATED │
                       │  Session Active│
                       └───────────────┘
```

### 3.3 TOTP Implementation (RFC 6238)

```
Parameters:
- Digits: 6
- Period: 30 seconds
- Algorithm: HMAC-SHA256
- Window: ±1 (allow clock drift)
- Secret Size: 20 bytes (160 bits)

URI Format:
otpauth://totp/SecureVault:user@email.com
    ?secret=BCRY...
    &issuer=SecureVault
    &algorithm=SHA256
    &digits=6
    &period=30
```

### 3.4 Passkey Implementation

**COSE_Key Structure** (P-256):
```
Map(5) {
  1: 2,           // Key Type: EC2
  3: -7,          // Algorithm: ES256
 -1: 1,           // Curve: P-256
 -2: <32 bytes>,  // X coordinate
 -3: <32 bytes>   // Y coordinate
}
```

**Verification Flow**:
1. Parse authenticator data (RP ID hash, flags, sign count)
2. Verify user presence flag
3. Build signature base: authData || SHA3(clientDataJSON)
4. Verify ECDSA signature against stored public key
5. Update sign count (prevent replay)

---

## 4. Architecture

### 4.1 Module Structure

```
securevault-core/
├── src/
│   ├── lib.rs              # Main entry, exports
│   │
│   ├── crypto/
│   │   ├── mod.rs         # Module exports
│   │   ├── ml_kem.rs      # Kyber-768 + X25519 + HKDF
│   │   ├── argon2.rs      # Argon2id KDF
│   │   ├── totp.rs        # RFC 6238 TOTP
│   │   ├── passkey.rs     # WebAuthn/FIDO2
│   │   ├── sha3.rs        # SHA3-256/384/512
│   │   ├── ml_dsa.rs      # Dilithium (stub)
│   │   ���─��� sphincs.rs     # SPHINCS+ (stub)
│   │   ├── rng.rs         # ChaCha20 CSPRNG
│   │   ├── hybrid.rs      # Hybrid KEM wrapper
│   │   └── poly.rs        # Polynomial arithmetic
│   │
│   ├── storage/
│   │   ├── mod.rs         # Vault, PasswordEntry, SecureVault
│   │   └── (encrypted binary format)
│   │
│   ├── auth/
│   │   └── mod.rs         # AuthenticationSession state machine
│   │
│   ├── p2p/
│   │   └── mod.rs         # Peer-to-peer sync (UDP/TCP)
│   │
│   ├── behavior/
│   │   └── mod.rs         # Behavioral analysis
│   │
│   └── passkey/
│       └── mod.rs         # Passkey management
│
└── Cargo.toml

android/
└── app/
    └── src/main/
        ├── java/com/securevault/
        │   ├── SecureVaultApp.kt
        │   ├── MainActivity.kt
        │   ├── auth/
        │   │   └── SecureVaultAuthManager.kt
        │   └── ui/
        │       ├── screens/
        │       │   ├── LockScreen.kt
        │       │   ├── VaultScreen.kt
        │       │   └── ...
        │       ├── components/
        │       │   └── GlassComponents.kt
        │       └── theme/
        └── cpp/
            └── securevault_crypto.c
                (Argon2id, X25519, HKDF, TOTP in C)

windows/
├── src/
│   ├── commands/
│   │   ├── auth.tsx       # useAuth hook
│   │   ├── LoginScreen.tsx
│   │   └── ...
│   ├── main.rs
│   └── App.tsx
├── Cargo.toml
├── tauri.conf.json
└── package.json
```

### 4.2 Binary Vault Format

```
┌──────────────────────────────────────────────────────────┐
│                    VAULT FILE FORMAT                      │
├──────────────────────────────────────────────────────────┤
│  Offset    │  Size     │  Description                    │
├────────────┼────────────┼─────────────────────────────────┤
│  0x0000    │  32       │  Salt (Argon2id)               │
│  0x0020    │  1088     │  ML-KEM Ciphertext              │
│  0x0460    │  N        │  ChaCha20 Encrypted Data        │
│            │           │  [Nonce | Ciphertext | AuthTag] │
└────────────┴────────────┴─────────────────────────────────┘
```

### 4.3 Android Architecture

- **UI**: Jetpack Compose with Material 3
- **Native Crypto**: JNI bridge to Rust core + C implementation
- **Storage**: EncryptedSharedPreferences + encrypted vault file
- **Biometric**: AndroidX Biometric API
- **Passkey**: Credential Manager API (Android 14+)

### 4.4 Windows Architecture

- **Framework**: Tauri 2.0 + React/TypeScript
- **UI Styling**: Glassmorphism (CSS)
- **WebAuthn**: Native navigator.credentials API
- **Build**: Cargo + npm, outputs .exe and .msi

---

## 5. Security Considerations

### 5.1 Memory Protection

| Technique | Implementation |
|-----------|----------------|
| Zeroizing | `zeroize` crate on sensitive types |
| Secure Drop | `Drop` impl clears master key |
| No Swap | mlock() where available |
| Clear on Lock | Session key zeroized on vault lock |

### 5.2 Attack Mitigation

| Threat | Mitigation |
|--------|------------|
| GPU Brute-force | Argon2id (64MB memory) |
| Quantum Decryption | Hybrid KEM (X25519 + ML-KEM) |
| Replay Attacks | Sign count + timestamps |
| Session Hijacking | Auto-lock timeout |
| Biometric Spoofing | Require user presence |

### 5.3 Security Audit Checklist

- [x] No external crypto libraries used
- [x] Constant-time comparisons
- [x] Secure random generation
- [x] Salt uniqueness per vault
- [x] Auth tag verification
- [x] Memory zeroization

---

## 6. Build & Deployment

### 6.1 CI/CD Pipeline

**GitHub Actions** (.github/workflows/build.yml):

```yaml
Jobs:
  - test-rust        # cargo test, clippy, fmt
  - security-audit   # cargo audit
  - build-android    # ./gradlew assembleDebug
  - build-windows    # cargo tauri build
  - release          # GitHub Release + artifacts
```

### 6.2 Build Commands

```bash
# Android
cd android
./gradlew assembleRelease

# Windows
cd windows
cargo tauri build --release

# Rust Core (testing)
cd securevault-core
cargo test
cargo build --release
```

### 6.3 Artifacts

| Platform | Artifact | Size |
|----------|----------|------|
| Android | securevault-release.apk | ~15MB |
| Windows | SecureVault_x.x.x_x64.exe | ~8MB |

---

## 7. API Reference

### 7.1 Core Cryptography

```rust
use securevault_core::{
    // Key Derivation
    argon2id_hash,           // password, salt -> key
    
    // Hybrid KEM
    ml_kem::Kyber768Engine::keygen,
    ml_kem::Kyber768Engine::encaps,
    ml_kem::Kyber768Engine::decaps,
    ml_kem::x25519::keygen,
    ml_kem::x25519::shared_secret,
    
    // TOTP
    generate_totp_secret,
    verify_totp_code,
    TotpManager,
    
    // Passkey
    verify_passkey_signature,
    PasskeyManager,
    
    // Vault
    SecureVault, PasswordEntry,
};
```

### 7.2 Authentication

```rust
use securevault_core::{
    AuthenticationSession,
    LoginState, LoginConfig, AuthError,
    create_login_config,
};

// Create session
let mut session = AuthenticationSession::new();
session.set_totp_secret(secret);

// Password flow
session.start_master_password_flow();
session.verify_master_password(password, salt)?;

// TOTP flow (if enabled)
session.verify_totp(totp_code)?;

// Passkey
session.start_passkey_flow();
session.verify_passkey(credential_id)?;
```

### 7.3 Android JNI

```c
// Key functions in securevault_crypto.h
int32_t hybrid_kem_keygen(...);
int32_t hybrid_kem_encaps(...);
int32_t argon2id_hash(...);
int32_t generate_secure_password(...);
int32_t calculate_password_strength(...);
```

---

## 8. Testing Vectors

### Argon2id
```
Input:  password = "test_password"
        salt    = "unique_salt_16xxxxxx"
Output: 32-byte key (deterministic)
```

### TOTP
```
Secret:  20 bytes (random)
Code:    6-digit, refreshes every 30s
Window:  ±1 (90 second validity)
```

### Hybrid KEM
```
Classical Shared: 32 bytes (X25519)
Quantum Shared:  32 bytes (Kyber-768)
Combined (HKDF):  32 bytes
```

---

## 9. Future Development

### Phase 3 (Planned)
- ML-DSA full implementation
- SPHINCS+ full implementation  
- iOS native client
- Encrypted note attachments

### Phase 4 (Roadmap)
- Threshold signatures (3-of-5)
- Hardware key integration (YubiKey)
- Post-quantum TLS for P2P sync

---

## 10. License & Credits

- **License**: MIT
- **Lead Developer**: PQ-Vault Team
- **Cryptography**: Custom Rust implementation (no external libs)

---

*This document describes PQ-Vault v2.0. All cryptographic implementations are from scratch without reliance on external crypto libraries.*