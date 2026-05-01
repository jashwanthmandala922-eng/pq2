#![allow(unused_variables, dead_code)]
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AuthenticationMethod {
    MasterPassword,
    Passkey,
    Biometric,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum LoginState {
    Initial,
    WaitingForMasterPassword,
    WaitingForTotp,
    WaitingForPasskey,
    BiometricPrompt,
    Authenticated,
    Locked,
    Failed(AuthError),
}

impl Default for LoginState {
    fn default() -> Self {
        Self::Initial
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginConfig {
    pub require_totp: bool,
    pub allow_passkey: bool,
    pub allow_biometric: bool,
    pub totp_enabled: bool,
    pub passkey_enabled: bool,
    pub failed_attempts: u32,
    pub lockout_until: Option<u64>,
}

impl Default for LoginConfig {
    fn default() -> Self {
        Self {
            require_totp: true,
            allow_passkey: true,
            allow_biometric: true,
            totp_enabled: false,
            passkey_enabled: false,
            failed_attempts: 0,
            lockout_until: None,
        }
    }
}

impl Zeroize for LoginConfig {
    fn zeroize(&mut self) {
        self.require_totp.zeroize();
        self.failed_attempts.zeroize();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AuthError {
    InvalidMasterPassword,
    InvalidTotpCode,
    PasskeyVerificationFailed,
    BiometricNotAvailable,
    BiometricNotEnrolled,
    BiometricLockout,
    TooManyFailedAttempts,
    SessionExpired,
    VaultLocked,
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::InvalidMasterPassword => write!(f, "Invalid master password"),
            AuthError::InvalidTotpCode => write!(f, "Invalid TOTP code"),
            AuthError::PasskeyVerificationFailed => write!(f, "Passkey verification failed"),
            AuthError::BiometricNotAvailable => write!(f, "Biometric authentication not available"),
            AuthError::BiometricNotEnrolled => write!(f, "No biometric credentials enrolled"),
            AuthError::BiometricLockout => write!(f, "Biometric locked due to too many failed attempts"),
            AuthError::TooManyFailedAttempts => write!(f, "Too many failed attempts - account locked"),
            AuthError::SessionExpired => write!(f, "Session expired"),
            AuthError::VaultLocked => write!(f, "Vault is locked"),
        }
    }
}

pub struct AuthenticationSession {
    state: LoginState,
    config: LoginConfig,
    master_key: Option<ZeroizingMasterKey>,
    totp_secret: Option<[u8; 20]>,
    passkey_credentials: Vec<PasskeyCredentialRef>,
    session_start: Option<u64>,
    max_failed_attempts: u32,
}

#[derive(Clone)]
struct PasskeyCredentialRef {
    credential_id: Vec<u8>,
}

impl Zeroize for PasskeyCredentialRef {
    fn zeroize(&mut self) {
        self.credential_id.zeroize();
    }
}

#[derive(ZeroizeOnDrop, Default)]
pub struct ZeroizingMasterKey {
    key: Vec<u8>,
}

impl Zeroize for ZeroizingMasterKey {
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

impl AuthenticationSession {
    pub fn new() -> Self {
        Self {
            state: LoginState::Initial,
            config: LoginConfig::default(),
            master_key: None,
            totp_secret: None,
            passkey_credentials: vec![],
            session_start: None,
            max_failed_attempts: 5,
        }
    }

    pub fn with_config(config: LoginConfig, max_failed_attempts: u32) -> Self {
        Self {
            state: LoginState::Initial,
            config,
            master_key: None,
            totp_secret: None,
            passkey_credentials: vec![],
            session_start: None,
            max_failed_attempts,
        }
    }

    pub fn set_totp_secret(&mut self, secret: [u8; 20]) {
        self.totp_secret = Some(secret);
        self.config.totp_enabled = true;
    }

    pub fn add_passkey_credential(&mut self, credential_id: Vec<u8>) {
        self.passkey_credentials.push(PasskeyCredentialRef { credential_id });
        self.config.passkey_enabled = true;
    }

    pub fn get_state(&self) -> &LoginState {
        &self.state
    }

    pub fn get_required_method(&self) -> AuthenticationMethod {
        if self.config.totp_enabled && self.config.require_totp {
            AuthenticationMethod::MasterPassword
        } else if self.config.passkey_enabled {
            AuthenticationMethod::Passkey
        } else if self.config.allow_biometric {
            AuthenticationMethod::Biometric
        } else {
            AuthenticationMethod::MasterPassword
        }
    }

    pub fn start_master_password_flow(&mut self) -> LoginState {
        if self.is_locked() {
            self.state = LoginState::Locked;
            return self.state.clone();
        }

        if self.config.totp_enabled && self.config.require_totp {
            self.state = LoginState::WaitingForMasterPassword;
        } else {
            self.state = LoginState::WaitingForMasterPassword;
        }
        
        self.state.clone()
    }

    pub fn start_passkey_flow(&mut self) -> Option<LoginState> {
        if !self.config.passkey_enabled {
            return None;
        }
        
        if self.is_locked() {
            self.state = LoginState::Locked;
            return Some(self.state.clone());
        }

        self.state = LoginState::WaitingForPasskey;
        Some(self.state.clone())
    }

    pub fn start_biometric_flow(&mut self) -> Option<LoginState> {
        if !self.config.allow_biometric {
            return None;
        }
        
        if self.is_locked() {
            self.state = LoginState::Locked;
            return Some(self.state.clone());
        }

        self.state = LoginState::BiometricPrompt;
        Some(self.state.clone())
    }

    pub fn verify_master_password(&mut self, password: &str, salt: &[u8]) -> Result<LoginState, AuthError> {
        if self.state != LoginState::WaitingForMasterPassword {
            return Err(AuthError::VaultLocked);
        }

        let key = crate::argon2id_hash(password.as_bytes(), salt);
        
        if key.len() < 32 {
            return self.handle_failed_attempt(AuthError::InvalidMasterPassword);
        }
        
        let mut key_bytes = key;
        key_bytes.resize(64, 0);
        
        self.master_key = Some(ZeroizingMasterKey { key: key_bytes });

        if self.config.totp_enabled && self.config.require_totp {
            self.state = LoginState::WaitingForTotp;
        } else {
            self.authenticate_success();
        }

        Ok(self.state.clone())
    }

    pub fn verify_totp(&mut self, code: &str) -> Result<LoginState, AuthError> {
        if self.state != LoginState::WaitingForTotp {
            return Err(AuthError::VaultLocked);
        }

        let secret = self.totp_secret
            .ok_or(AuthError::InvalidTotpCode)?;

        if crate::verify_totp_code(&secret, code) {
            self.authenticate_success();
            Ok(self.state.clone())
        } else {
            self.handle_failed_attempt(AuthError::InvalidTotpCode)
        }
    }

    pub fn verify_passkey(&mut self, credential_id: &[u8]) -> Result<LoginState, AuthError> {
        if self.state != LoginState::WaitingForPasskey {
            return Err(AuthError::VaultLocked);
        }

        let valid = self.passkey_credentials
            .iter()
            .any(|c| c.credential_id == credential_id);

        if valid {
            self.authenticate_success();
            Ok(self.state.clone())
        } else {
            self.handle_failed_attempt(AuthError::PasskeyVerificationFailed)
        }
    }

    pub fn verify_biometric(&mut self) -> Result<LoginState, AuthError> {
        if !self.config.allow_biometric {
            return Err(AuthError::BiometricNotAvailable);
        }

        if !self.passkey_credentials.is_empty() {
            self.authenticate_success();
            Ok(self.state.clone())
        } else {
            self.handle_failed_attempt(AuthError::BiometricNotEnrolled)
        }
    }

    pub fn lock(&mut self) {
        self.state = LoginState::Locked;
        
        if let Some(ref mut key) = self.master_key {
            key.zeroize();
        }
        self.master_key = None;
        self.session_start = None;
    }

    pub fn get_session_key(&self) -> Option<&ZeroizingMasterKey> {
        if self.state == LoginState::Authenticated {
            self.master_key.as_ref()
        } else {
            None
        }
    }

pub fn is_locked(&mut self) -> bool {
        if let Some(lockout) = self.config.lockout_until {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            if now < lockout {
                return true;
            }
            self.config.lockout_until = None;
            self.config.failed_attempts = 0;
        }
        self.state != LoginState::Authenticated || self.session_start.is_none()
    }

    fn authenticate_success(&mut self) {
        self.state = LoginState::Authenticated;
        self.config.failed_attempts = 0;
        self.session_start = Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        );
    }

    fn handle_failed_attempt(&mut self, error: AuthError) -> Result<LoginState, AuthError> {
        self.config.failed_attempts += 1;
        
        if self.config.failed_attempts >= self.max_failed_attempts {
            let lockout_duration = 300u64 * (self.config.failed_attempts as u64 / self.max_failed_attempts as u64);
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            self.config.lockout_until = Some(now + lockout_duration);
            
            self.state = LoginState::Locked;
            self.state = LoginState::Failed(AuthError::TooManyFailedAttempts);
        } else {
            self.state = LoginState::Failed(error.clone());
        }
        
        Err(error)
    }

    pub fn require_totp(&mut self, require: bool) {
        self.config.require_totp = require;
    }

    pub fn is_totp_required(&self) -> bool {
        self.config.totp_enabled && self.config.require_totp
    }
}

impl Default for AuthenticationSession {
    fn default() -> Self {
        Self::new()
    }
}

pub fn create_login_config(totp_enabled: bool, passkey_count: usize) -> LoginConfig {
    LoginConfig {
        require_totp: true,
        allow_passkey: passkey_count > 0,
        allow_biometric: true,
        totp_enabled,
        passkey_enabled: passkey_count > 0,
        failed_attempts: 0,
        lockout_until: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_auth_flow_master_password_only() {
        let mut session = AuthenticationSession::new();
        
        session.start_master_password_flow();
        assert_eq!(session.get_state(), &LoginState::WaitingForMasterPassword);
    }
    
    #[test]
    fn test_auth_with_totp() {
        let mut session = AuthenticationSession::new();
        
        let secret = [0u8; 20];
        session.set_totp_secret(secret);
        
        session.start_master_password_flow();
        
        session.verify_master_password("test", b"testsalt").ok();
        
        assert_eq!(session.get_state(), LoginState::WaitingForTotp);
    }
    
    #[test]
    fn test_max_failed_attempts() {
        let mut session = AuthenticationSession::with_config(LoginConfig::default(), 3);
        
        for _ in 0..3 {
            let result = session.verify_master_password("wrong", b"salt");
            assert!(result.is_err());
        }
        
        assert!(matches!(session.get_state(), LoginState::Failed(AuthError::TooManyFailedAttempts)));
    }
}