#![allow(unused_variables, dead_code, unused_imports, unused_assignments)]
use serde::{Deserialize, Serialize};

pub mod crypto;
pub mod storage;
pub mod p2p;
pub mod behavior;
pub mod passkey;
pub mod auth;

pub use crypto::{Sha3_256, ChaChaRng, argon2id_hash, hybrid::HybridKeyPair, 
    totp::{TotpManager, verify_totp_code, generate_totp_secret},
    passkey::{PasskeyCredential, PasskeyVerification, verify_passkey_signature, PasskeyError}};
pub use storage::{SecureVault, PasswordEntry, Vault, VaultError, SensitiveString};
pub use p2p::{
    P2PManager, PeerInfo, P2PMessage, P2PError,
    dht_p2p::{P2PSyncManager, P2PConfig, derive_account_id, SyncEntry, SyncResult as DhtSyncResult, P2PError as DhtP2PError, SyncEntryUpdate, SyncAck, SyncQueue, VectorClock, SyncBroadcastResult, ManualSyncResult, SyncStatus},
};
pub use behavior::{BehavioralAnalyzer, BehavioralProfile, CompositeAnalysis, ThreatLevel};
pub use passkey::{PasskeyManager, PasskeyCredential as PkCredential, PasskeyError as PkError};
pub use auth::{AuthenticationSession, LoginState, LoginConfig, AuthError, AuthenticationMethod, create_login_config};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub auto_lock_minutes: u32,
    pub biometric_enabled: bool,
    pub p2p_enabled: bool,
    pub dark_mode: bool,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            auto_lock_minutes: 5,
            biometric_enabled: true,
            p2p_enabled: true,
            dark_mode: false,
        }
    }
}

pub fn generate_secure_password(length: u32, include_special: bool) -> String {
    let charset = if include_special {
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+"
    } else {
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    };
    
    let mut password = String::with_capacity(length as usize);
    let chars: Vec<char> = charset.chars().collect();
    let mut rng = ChaChaRng::new(b"SecureVault-PasswordGen!");
    let mut random_bytes = vec![0u8; length as usize];
    rng.fill_bytes(&mut random_bytes);
    
    for byte in random_bytes {
        let idx = (byte as usize) % chars.len();
        password.push(chars[idx]);
    }
    
    password
}

pub fn verify_password_strength(password: &str) -> PasswordStrength {
    let length = password.len();
    let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_special = password.chars().any(|c| !c.is_alphanumeric());
    
    let score = [has_lower, has_upper, has_digit, has_special]
        .iter()
        .filter(|&&x| x)
        .count();
    
    match (length, score) {
        (0..=7, _) => PasswordStrength::VeryWeak,
        (8..=11, 0..=1) => PasswordStrength::Weak,
        (8..=11, 2) => PasswordStrength::Fair,
        (12.., 2) => PasswordStrength::Good,
        (12.., 3) => PasswordStrength::Strong,
        (_, 4) => PasswordStrength::VeryStrong,
        _ => PasswordStrength::Fair,
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum PasswordStrength {
    VeryWeak,
    Weak,
    Fair,
    Good,
    Strong,
    VeryStrong,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_password_generation() {
        let password = generate_secure_password(16, true);
        assert_eq!(password.len(), 16);
    }
    
    #[test]
    fn test_password_strength() {
        assert_eq!(verify_password_strength("abc"), PasswordStrength::VeryWeak);
        assert_eq!(verify_password_strength("abcd1234"), PasswordStrength::Weak);
        assert_eq!(verify_password_strength("Abcd1234!"), PasswordStrength::Fair);
        assert_eq!(verify_password_strength("Abcd1234!@#$"), PasswordStrength::Strong);
    }
}