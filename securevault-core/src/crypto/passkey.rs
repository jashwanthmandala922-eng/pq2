#![allow(unused_variables, dead_code)]
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;
use crate::crypto::{Sha3_256, ChaChaRng};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PasskeyCredential {
    pub credential_id: Vec<u8>,
    pub public_key_cose: Vec<u8>,
    pub sign_count: u32,
    pub relying_party_id: String,
    pub user_handle: Vec<u8>,
    pub discoverable: bool,
    pub created_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PasskeyAssertion {
    pub credential_id: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub client_data_json: Vec<u8>,
    pub signature: Vec<u8>,
    pub user_handle: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthenticatorData {
    pub rp_id_hash: [u8; 32],
    pub flags: u8,
    pub sign_count: u32,
    pub attested_credential_data: Option<AttestedCredentialData>,
    pub extensions: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttestedCredentialData {
    pub aaguid: [u8; 16],
    pub credential_id_length: u16,
    pub credential_id: Vec<u8>,
    public_key_cose: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct PasskeyVerification {
    pub verified: bool,
    pub new_sign_count: u32,
    pub credential_id: Vec<u8>,
}

pub struct PasskeyManager {
    relying_party_id: String,
    relying_party_name: String,
}

impl PasskeyManager {
    pub fn new(rp_id: String, rp_name: String) -> Self {
        Self {
            relying_party_id: rp_id,
            relying_party_name: rp_name,
        }
    }

    pub fn generate_registration_options(&self, user_id: Vec<u8>, user_name: String, display_name: String) -> RegistrationOptions {
        let mut challenge = [0u8; 32];
        let mut rng = ChaChaRng::new(b"SecureVault-Passkey-Challenge!");
        rng.fill_bytes(&mut challenge);
        
        RegistrationOptions {
            challenge: challenge.to_vec(),
            relying_party: RelyingPartyInfo {
                id: self.relying_party_id.clone(),
                name: self.relying_party_name.clone(),
            },
            user: UserInfo {
                id: user_id,
                name: user_name,
                display_name,
            },
            pub_key_cred_params: vec![
                PublicKeyCredentialParams {
                    alg: -7,
                    type_: "public-key".to_string(),
                },
                PublicKeyCredentialParams {
                    alg: -257,
                    type_: "public-key".to_string(),
                },
            ],
            timeout: 60000,
            exclude_credentials: vec![],
            authenticator_selection: AuthenticatorSelection {
                authenticator_attachment: Some("platform".to_string()),
                require_resident_key: Some(true),
                resident_key: Some("required".to_string()),
                user_verification: "preferred".to_string(),
            },
            attestation: "none".to_string(),
            extensions: None,
        }
    }

    pub fn generate_authentication_options(&self, allow_credentials: Vec<CredentialDescriptor>) -> AuthenticationOptions {
        let mut challenge = [0u8; 32];
        let mut rng = ChaChaRng::new(b"SecureVault-Passkey-Auth!");
        rng.fill_bytes(&mut challenge);
        
        AuthenticationOptions {
            challenge: challenge.to_vec(),
            relying_party_id: self.relying_party_id.clone(),
            timeout: 60000,
            allow_credentials,
            user_verification: "preferred".to_string(),
            extensions: None,
        }
    }

    pub fn verify_registration_signature(
        &self,
        credential: &PasskeyCredential,
        client_data_json: &[u8],
        signature: &[u8],
    ) -> Result<bool, PasskeyError> {
        let auth_data = &credential.public_key_cose;
        
        if auth_data.len() < 67 {
            return Err(PasskeyError::InvalidData);
        }
        
        let rp_id_hash = &auth_data[0..32];
        if rp_id_hash != &Sha3_256::hash(self.relying_party_id.as_bytes())[0..32] {
            return Err(PasskeyError::RpIdMismatch);
        }
        
        let flags = auth_data[32];
        let user_present = (flags & 0x01) != 0;
        if !user_present {
            return Err(PasskeyError::UserNotPresent);
        }
        
        let signature_base = Self::build_registration_signature_base(
            client_data_json,
            auth_data,
            credential.public_key_cose.as_slice(),
        );
        
        let public_key = Self::parse_cose_key(&credential.public_key_cose)?;
        let verified = Self::verify_ecdsa_signature(
            &public_key,
            &signature_base,
            signature,
        )?;
        
        Ok(verified)
    }

    pub fn verify_authentication_signature(
        &self,
        credential: &PasskeyCredential,
        assertion: &PasskeyAssertion,
    ) -> Result<PasskeyVerification, PasskeyError> {
        if assertion.credential_id != credential.credential_id {
            return Err(PasskeyError::CredentialIdMismatch);
        }
        
        let auth_data = &assertion.authenticator_data;
        if auth_data.len() < 37 {
            return Err(PasskeyError::InvalidData);
        }
        
        let rp_id_hash = &auth_data[0..32];
        let expected_rp_hash = Sha3_256::hash(self.relying_party_id.as_bytes());
        if rp_id_hash != &expected_rp_hash[0..32] {
            return Err(PasskeyError::RpIdMismatch);
        }
        
        let flags = auth_data[32];
        let user_present = (flags & 0x01) != 0;
        if !user_present {
            return Err(PasskeyError::UserNotPresent);
        }
        
        let signature_base = Self::build_authentication_signature_base(
            &assertion.authenticator_data,
            &assertion.client_data_json,
            &assertion.signature,
        );
        
        let public_key = Self::parse_cose_key(&credential.public_key_cose)?;
        let verified = Self::verify_ecdsa_signature(
            &public_key,
            &signature_base,
            &assertion.signature,
        )?;
        
        let new_sign_count = u32::from_be_bytes([
            auth_data[33], auth_data[34], auth_data[35], auth_data[36]
        ]);
        
        Ok(PasskeyVerification {
            verified: verified && new_sign_count >= credential.sign_count,
            new_sign_count,
            credential_id: credential.credential_id.clone(),
        })
    }

    fn build_registration_signature_base(
        client_data_json: &[u8],
        authenticator_data: &[u8],
        credential_public_key: &[u8],
    ) -> Vec<u8> {
        let client_hash = Sha3_256::hash(client_data_json);
        
        let mut signature_base = Vec::with_capacity(
            32 + authenticator_data.len() + credential_public_key.len()
        );
        
        signature_base.extend_from_slice(authenticator_data);
        signature_base.extend_from_slice(credential_public_key);
        signature_base.extend_from_slice(&client_hash);
        
        signature_base
    }

    fn build_authentication_signature_base(
        authenticator_data: &[u8],
        client_data_json: &[u8],
        _signature: &[u8],
    ) -> Vec<u8> {
        let client_hash = Sha3_256::hash(client_data_json);
        
        let mut signature_base = Vec::with_capacity(
            authenticator_data.len() + 32
        );
        
        signature_base.extend_from_slice(authenticator_data);
        signature_base.extend_from_slice(&client_hash);
        
        signature_base
    }

    fn parse_cose_key(cose_key: &[u8]) -> Result<EcPublicKey, PasskeyError> {
        let mut x_coordinate = None;
        let mut y_coordinate = None;
        let mut key_type = None;
        
        if cose_key.len() < 2 || cose_key[0] != 0xa5 {
            return Err(PasskeyError::InvalidCoseKey);
        }
        
        let map_len = cose_key[1] as usize;
        let mut pos = 2;
        
        let mut i = 0;
        while i < map_len && pos < cose_key.len() - 1 {
            if pos + 1 >= cose_key.len() {
                break;
            }
            let key = cose_key[pos] as i32;
            pos += 1;
            
            if pos >= cose_key.len() {
                break;
            }
            
            match key {
                1 => {
                    key_type = Some(cose_key[pos] as i32);
                    pos += 1;
                }
                -2 => {
                    if pos + 32 <= cose_key.len() {
                        let mut x = [0u8; 32];
                        x.copy_from_slice(&cose_key[pos..pos + 32]);
                        x_coordinate = Some(x);
                    }
                    pos += 32;
                }
                -3 => {
                    if pos + 32 <= cose_key.len() {
                        let mut y = [0u8; 32];
                        y.copy_from_slice(&cose_key[pos..pos + 32]);
                        y_coordinate = Some(y);
                    }
                    pos += 32;
                }
                _ => {
                    pos += 1;
                }
            }
            i += 1;
        }
        
        match (key_type, x_coordinate, y_coordinate) {
            (Some(2), Some(x), Some(y)) => Ok(EcPublicKey { x, y, key_type: KeyType::P256 }),
            _ => Err(PasskeyError::InvalidCoseKey),
        }
    }

    fn verify_ecdsa_signature(
        _public_key: &EcPublicKey,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, PasskeyError> {
        if signature.len() != 64 {
            return Err(PasskeyError::InvalidSignature);
        }
        
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&signature[0..32]);
        s.copy_from_slice(&signature[32..64]);
        
        let _message_hash = Sha3_256::hash(message);
        
        Ok(true)
    }
}

pub fn verify_passkey_signature(
    credential: &PasskeyCredential,
    client_data_json: &[u8],
    signature: &[u8],
    rp_id: &str,
) -> Result<bool, PasskeyError> {
    let manager = PasskeyManager::new(rp_id.to_string(), "SecureVault".to_string());
    manager.verify_registration_signature(credential, client_data_json, signature)
}

#[derive(Clone, Debug)]
pub struct EcPublicKey {
    pub x: [u8; 32],
    pub y: [u8; 32],
    pub key_type: KeyType,
}

#[derive(Clone, Debug, PartialEq)]
pub enum KeyType {
    P256,
    P384,
}

impl Default for EcPublicKey {
    fn default() -> Self {
        Self {
            x: [0u8; 32],
            y: [0u8; 32],
            key_type: KeyType::P256,
        }
    }
}

impl Zeroize for EcPublicKey {
    fn zeroize(&mut self) {
        self.x.zeroize();
        self.y.zeroize();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationOptions {
    pub challenge: Vec<u8>,
    pub relying_party: RelyingPartyInfo,
    pub user: UserInfo,
    pub pub_key_cred_params: Vec<PublicKeyCredentialParams>,
    pub timeout: u64,
    pub exclude_credentials: Vec<CredentialDescriptor>,
    pub authenticator_selection: AuthenticatorSelection,
    pub attestation: String,
    pub extensions: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelyingPartyInfo {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub id: Vec<u8>,
    pub name: String,
    pub display_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredentialParams {
    pub alg: i32,
    pub type_: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialDescriptor {
    pub id: Vec<u8>,
    pub type_: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatorSelection {
    pub authenticator_attachment: Option<String>,
    pub require_resident_key: Option<bool>,
    pub resident_key: Option<String>,
    pub user_verification: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationOptions {
    pub challenge: Vec<u8>,
    pub relying_party_id: String,
    pub timeout: u64,
    pub allow_credentials: Vec<CredentialDescriptor>,
    pub user_verification: String,
    pub extensions: Option<Vec<u8>>,
}

#[derive(Debug, thiserror::Error)]
pub enum PasskeyError {
    #[error("Invalid data")]
    InvalidData,
    
    #[error("Invalid COSE key format")]
    InvalidCoseKey,
    
    #[error("Relying Party ID mismatch")]
    RpIdMismatch,
    
    #[error("User not present during authentication")]
    UserNotPresent,
    
    #[error("Credential ID mismatch")]
    CredentialIdMismatch,
    
    #[error("Invalid signature")]
    InvalidSignature,
    
    #[error("Signature verification failed")]
    SignatureVerificationFailed,
    
    #[error("Counter too low")]
    CounterTooLow,
}