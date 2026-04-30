//
//  SecureVault Native Crypto Library
//  Post-Quantum Cryptography Implementation
//  Production Ready - Hybrid KEM + Argon2id
//

#ifndef SECUREVAULT_CRYPTO_H
#define SECUREVAULT_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================
// HYBRID KEY ENCAPSULATION MECHANISM (X25519 + ML-KEM-768)
// ============================================================

// Hybrid KEM Key Generation (X25519 + Kyber-768 combined)
int32_t hybrid_kem_keygen(
    uint8_t* classical_public,    // Output: 32 bytes (X25519)
    uint8_t* classical_secret,    // Output: 32 bytes (X25519)
    uint8_t* quantum_public,     // Output: 1184 bytes (Kyber-768)
    uint8_t* quantum_secret      // Output: 2400 bytes (Kyber-768)
);

// Hybrid KEM Encapsulation (HKDF from both secrets)
int32_t hybrid_kem_encaps(
    const uint8_t* classical_public,  // Input: 32 bytes
    const uint8_t* quantum_public,     // Input: 1184 bytes
    uint8_t* classical_ciphertext,    // Output: 32 bytes (ephemeral X25519)
    uint8_t* quantum_ciphertext,      // Output: 1088 bytes (Kyber)
    uint8_t* shared_secret           // Output: 32 bytes (HKDF-derived)
);

// Hybrid KEM Decapsulation
int32_t hybrid_kem_decaps(
    const uint8_t* classical_secret,  // Input: 32 bytes
    const uint8_t* quantum_secret,    // Input: 2400 bytes
    const uint8_t* classical_ciphertext,  // Input: 32 bytes
    const uint8_t* quantum_ciphertext,    // Input: 1088 bytes
    uint8_t* shared_secret           // Output: 32 bytes
);

// ============================================================
// ARGON2ID KEY DERIVATION (m=65536, t=3, p=4)
// ============================================================

// Argon2id Key Derivation
int32_t argon2id_hash(
    const uint8_t* password,     // Input: password data
    size_t password_len,
    const uint8_t* salt,          // Input: 16-64 bytes
    size_t salt_len,
    uint8_t* output              // Output: 32 bytes
);

// Argon2id with custom parameters
int32_t argon2id_hash_params(
    const uint8_t* password,
    size_t password_len,
    const uint8_t* salt,
    size_t salt_len,
    uint32_t memory_kb,          // Default: 65536
    uint32_t iterations,        // Default: 3
    uint32_t parallelism,       // Default: 4
    uint8_t* output
);

// ============================================================
// ML-KEM (Kyber-768) - Direct API
// ============================================================

int32_t ml_kem_768_keygen(
    uint8_t* public_key,    // Output: 1184 bytes
    uint8_t* secret_key    // Output: 2400 bytes
);

int32_t ml_kem_768_encaps(
    const uint8_t* public_key,  // Input: 1184 bytes
    uint8_t* ciphertext,        // Output: 1088 bytes
    uint8_t* shared_secret     // Output: 32 bytes
);

int32_t ml_kem_768_decaps(
    const uint8_t* secret_key,  // Input: 2400 bytes
    const uint8_t* ciphertext,  // Input: 1088 bytes
    uint8_t* shared_secret     // Output: 32 bytes
);

// ============================================================
// X25519 (Classical KEM)
// ============================================================

int32_t x25519_keygen(
    uint8_t* public_key,    // Output: 32 bytes
    uint8_t* secret_key     // Output: 32 bytes
);

int32_t x25519_shared_secret(
    const uint8_t* secret_key,   // Input: 32 bytes
    const uint8_t* public_key,   // Input: 32 bytes
    uint8_t* shared_secret      // Output: 32 bytes
);

// ============================================================
// ML-DSA (Dilithium-65)
// ============================================================

int32_t ml_dsa_65_sign(
    const uint8_t* secret_key,   // Input: 6080 bytes
    const uint8_t* message,     // Input: message data
    size_t message_len,
    uint8_t* signature         // Output: 4895 bytes
);

int32_t ml_dsa_65_verify(
    const uint8_t* public_key,  // Input: 4032 bytes
    const uint8_t* message,    // Input: message data
    size_t message_len,
    const uint8_t* signature   // Input: 4895 bytes
);

// ============================================================
// SPHINCS+
// ============================================================

int32_t sphincs_keygen(
    uint8_t* public_key,    // Output: 32 bytes
    uint8_t* secret_key    // Output: 64 bytes
);

int32_t sphincs_sign(
    const uint8_t* secret_key,   // Input: 64 bytes
    const uint8_t* message,     // Input: message data
    size_t message_len,
    uint8_t* signature        // Output: 7856 bytes
);

int32_t sphincs_verify(
    const uint8_t* public_key,  // Input: 32 bytes
    const uint8_t* message,     // Input: message data
    size_t message_len,
    const uint8_t* signature  // Input: 7856 bytes
);

// ============================================================
// SHA3 Hashing
// ============================================================

void sha3_256_hash(
    const uint8_t* input,
    size_t input_len,
    uint8_t* output         // Output: 32 bytes
);

void sha3_512_hash(
    const uint8_t* input,
    size_t input_len,
    uint8_t* output         // Output: 64 bytes
);

// ============================================================
// CSPRNG
// ============================================================

int32_t csprng_random_bytes(
    uint8_t* output,
    size_t output_len
);

// ============================================================
// Secure Memory Operations (for SensitiveString zeroizing)
// ============================================================

void secure_zero(
    uint8_t* data,
    size_t data_len
);

int32_t secure_compare(
    const uint8_t* a,
    const uint8_t* b,
    size_t len
);

// ============================================================
// High-level Vault Operations
// ============================================================

// Vault creation with Argon2id
int32_t vault_create(
    const char* master_password,
    uint8_t* salt_output,        // Output: 32 bytes
    uint8_t* encrypted_vault,   // Output: vault data
    size_t* vault_len
);

// Vault unlock with Argon2id + Hybrid KEM
int32_t vault_unlock(
    const char* master_password,
    const uint8_t* salt,        // Input: 32 bytes
    const uint8_t* encrypted_vault, // Input: vault data
    size_t vault_len,
    uint8_t* decrypted_data,   // Output
    size_t* decrypted_len
);

// Password entry management
int32_t vault_add_entry(
    const uint8_t* vault_key,   // Input: 64 bytes
    const char* title,
    const char* password,
    uint8_t* encrypted_entry,  // Output
    size_t* entry_len
);

int32_t vault_get_entry(
    const uint8_t* vault_key,   // Input: 64 bytes
    const uint8_t* encrypted_entry, // Input
    size_t entry_len,
    char* title_output,
    char* password_output,
    size_t max_password_len
);

// Password operations
int32_t generate_secure_password(
    uint8_t* output,
    size_t length,
    uint8_t include_special
);

int32_t calculate_password_strength(
    const char* password,
    uint8_t* strength_output    // Output: 0-4 (VeryWeak to VeryStrong)
);

// ============================================================
// Constants
// ============================================================

#define VAULT_VERSION                   2
#define ARGON2_DEFAULT_MEMORY_KB        65536
#define ARGON2_DEFAULT_ITERATIONS       3
#define ARGON2_DEFAULT_PARALLELISM      4

#define ML_KEM_768_PUBLIC_KEY_SIZE      1184
#define ML_KEM_768_SECRET_KEY_SIZE      2400
#define ML_KEM_768_CIPHERTEXT_SIZE      1088
#define ML_KEM_768_SHARED_SECRET_SIZE   32

#define X25519_KEY_SIZE                 32
#define HYBRID_SHARED_SECRET_SIZE       32

#define SALT_SIZE                       32
#define KEY_SIZE                        32

// Password strength levels
#define PASSWORD_VERY_WEAK   0
#define PASSWORD_WEAK        1
#define PASSWORD_FAIR        2
#define PASSWORD_STRONG      3
#define PASSWORD_VERY_STRONG 4

// Return codes
#define CRYPTO_SUCCESS            0
#define CRYPTO_ERROR             -1
#define CRYPTO_INVALID_PARAM     -2
#define CRYPTO_OUT_OF_MEMORY     -3
#define CRYPTO_AUTH_FAILURE      -4
#define CRYPTO_NOT_IMPLEMENTED  -5

#ifdef __cplusplus
}
#endif

#endif // SECUREVAULT_CRYPTO_H