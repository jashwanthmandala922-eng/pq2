#![allow(unused_variables, dead_code)]
pub mod poly;
pub mod sha3;
pub mod ml_kem;
pub mod ml_dsa;
pub mod sphincs;
pub mod rng;
pub mod hybrid;
pub mod argon2;
pub mod totp;
pub mod passkey;
pub mod hybrid_crypto;

pub use sha3::Sha3_256;
pub use rng::{ChaChaRng, quarter_round};
pub use argon2::argon2id_hash;
pub use totp::{TotpManager, verify_totp_code, generate_totp_secret};
pub use passkey::{PasskeyCredential, PasskeyVerification, verify_passkey_signature};
pub use ml_kem::Kyber768Engine;
pub use ml_dsa::{MlDsaPublicKey, MlDsaSecretKey, ml_dsa_keygen, ml_dsa_sign, ml_dsa_verify};
pub use sphincs::{SphincsPublicKey, SphincsSecretKey, sphincs_keygen, sphincs_sign, sphincs_verify};
pub use hybrid::{HybridKeyPair, ClassicalKeyPair, QuantumKeyPair, SharedSecret, HybridPublicKey, HybridCiphertext};