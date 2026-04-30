use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;
use crate::crypto::Sha3_256;

const ED25519_PUBLIC_KEY_SIZE: usize = 32;
const ED25519_SECRET_KEY_SIZE: usize = 64;
const P256_PUBLIC_KEY_SIZE: usize = 65;
const P256_SECRET_KEY_SIZE: usize = 32;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthenticatorAttachment {
    CrossPlatform,
    Platform,
    Any,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UserVerificationRequirement {
    Required,
    Preferred,
    Discouraged,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResidentKeyRequirement {
    Required,
    Preferred,
    Discouraged,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredentialDescriptor {
    pub r#type: String,
    pub id: Vec<u8>,
    pub transports: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredentialRpEntity {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredentialUserEntity {
    pub id: Vec<u8>,
    pub name: String,
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatorSelectionCriteria {
    pub authenticator_attachment: Option<AuthenticatorAttachment>,
    pub require_resident_key: bool,
    pub user_verification: UserVerificationRequirement,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredentialCreationOptions {
    pub rp: PublicKeyCredentialRpEntity,
    pub user: PublicKeyCredentialUserEntity,
    pub challenge: Vec<u8>,
    pub pub_key_cred_params: Vec<PubKeyCredParam>,
    pub timeout: Option<u32>,
    pub exclude_credentials: Option<Vec<PublicKeyCredentialDescriptor>>,
    pub authenticator_sel: Option<AuthenticatorSelectionCriteria>,
    pub attestation: AttestationConveyancePreference,
    pub extensions: Option<AuthenticationExtensions>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PubKeyCredParam {
    pub r#type: String,
    pub alg: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AttestationConveyancePreference {
    None,
    Indirect,
    Direct,
    Enterprise,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationExtensions {
    pub appid: Option<String>,
    pub tx_auth_simple: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredential {
    pub r#type: String,
    pub id: String,
    pub raw_id: Vec<u8>,
    pub response: AuthenticatorAssertionResponse,
    pub client_extension_results: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatorAssertionResponse {
    pub client_data_json: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub user_handle: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatorAttestationResponse {
    pub client_data_json: Vec<u8>,
    pub attestation_object: Vec<u8>,
    pub transports: Option<Vec<String>>,
    pub client_extension_results: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientDataJSON {
    pub r#type: String,
    pub challenge: String,
    pub origin: String,
    pub cross_origin: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationObject {
    pub fmt: String,
    pub auth_data: AttestationData,
    pub att_stmt: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationData {
    pub rp_id_hash: Vec<u8>,
    pub flags: u8,
    pub sign_count: u32,
    pub aaguid: Option<Vec<u8>>,
    pub credential_id: Option<Vec<u8>>,
    pub pub_key: Option<Vec<u8>>,
}

pub struct PasskeyManager {
    credentials: HashMap<String, PasskeyCredential>,
    relying_party_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyCredential {
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub user_id: Vec<u8>,
    pub sign_count: u32,
    pub created_at: u64,
    pub last_used: u64,
    pub transports: Vec<String>,
}

impl PasskeyManager {
    pub fn new(relying_party_id: String) -> Self {
        Self {
            credentials: HashMap::new(),
            relying_party_id,
        }
    }

    pub fn generate_registration_options(&self, user_id: &str, user_name: &str, display_name: Option<&str>) -> PublicKeyCredentialCreationOptions {
        let user_id_bytes = user_id.as_bytes().to_vec();
        
        let mut challenge = [0u8; 32];
        crate::crypto::ChaChaRng::new(b"SecureVault-passkey!").fill_bytes(&mut challenge);

        PublicKeyCredentialCreationOptions {
            rp: PublicKeyCredentialRpEntity {
                id: self.relying_party_id.clone(),
                name: "SecureVault".to_string(),
            },
            user: PublicKeyCredentialUserEntity {
                id: user_id_bytes,
                name: user_name.to_string(),
                display_name: display_name.map(String::from),
            },
            challenge: challenge.to_vec(),
            pub_key_cred_params: vec![
                PubKeyCredParam {
                    r#type: "public-key".to_string(),
                    alg: -7,
                },
                PubKeyCredParam {
                    r#type: "public-key".to_string(),
                    alg: -257,
                },
            ],
            timeout: Some(60000),
            exclude_credentials: None,
            authenticator_sel: Some(AuthenticatorSelectionCriteria {
                authenticator_attachment: None,
                require_resident_key: false,
                user_verification: UserVerificationRequirement::Preferred,
            }),
            attestation: AttestationConveyancePreference::None,
            extensions: None,
        }
    }

    pub fn verify_registration(
        &mut self,
        credential: PublicKeyCredential,
        expected_challenge: &[u8],
    ) -> Result<PasskeyCredential, PasskeyError> {
        let response = credential.response;

        let client_data: ClientDataJSON = serde_json::from_slice(&response.client_data_json)
            .map_err(|_| PasskeyError::InvalidResponse)?;

        if client_data.r#type != "webauthn.create" {
            return Err(PasskeyError::InvalidResponseType);
        }

        let challenge_decoded = base64_decode(&client_data.challenge)
            .map_err(|_| PasskeyError::InvalidChallenge)?;
        
        if challenge_decoded != expected_challenge {
            return Err(PasskeyError::ChallengeMismatch);
        }

        if !client_data.origin.contains(&self.relying_party_id) {
            return Err(PasskeyError::OriginMismatch);
        }

        let auth_data = parse_auth_data(&response.authenticator_data)?;

        let rp_id_hash = Sha3_256::hash(self.relying_party_id.as_bytes());
        if &auth_data.rp_id_hash[..] != &rp_id_hash[..] {
            return Err(PasskeyError::RpIdHashMismatch);
        }

        if auth_data.flags & 0x01 == 0 {
            return Err(PasskeyError::UserNotPresent);
        }

        let credential_id = auth_data.credential_id.ok_or(PasskeyError::NoCredentialId)?;
        let pub_key = auth_data.pub_key.ok_or(PasskeyError::NoPublicKey)?;
        
        let passkey = PasskeyCredential {
            credential_id: credential_id.clone(),
            public_key: pub_key,
            user_id: auth_data.user_id.unwrap_or_default(),
            sign_count: auth_data.sign_count,
            created_at: current_timestamp(),
            last_used: current_timestamp(),
            transports: vec!["internal".to_string()],
        };

        let credential_id_hex = hex_encode(&credential_id);
        self.credentials.insert(credential_id_hex, passkey.clone());

        Ok(passkey)
    }

    pub fn generate_authentication_options(
        &self,
        allow_credentials: Option<Vec<PublicKeyCredentialDescriptor>>,
    ) -> PublicKeyCredentialRequestOptions {
        let mut challenge = [0u8; 32];
        crate::crypto::ChaChaRng::new(b"SecureVault-passkey-auth!").fill_bytes(&mut challenge);

        PublicKeyCredentialRequestOptions {
            challenge: challenge.to_vec(),
            timeout: Some(60000),
            rp_id: Some(self.relying_party_id.clone()),
            allow_credentials,
            user_verification: UserVerificationRequirement::Preferred,
            extensions: None,
        }
    }

    pub fn verify_authentication(
        &mut self,
        credential: PublicKeyCredential,
        expected_challenge: &[u8],
    ) -> Result<PasskeyCredential, PasskeyError> {
        let response = credential.response;

        let client_data: ClientDataJSON = serde_json::from_slice(&response.client_data_json)
            .map_err(|_| PasskeyError::InvalidResponse)?;

        if client_data.r#type != "webauthn.get" {
            return Err(PasskeyError::InvalidResponseType);
        }

        let challenge_decoded = base64_decode(&client_data.challenge)
            .map_err(|_| PasskeyError::InvalidChallenge)?;
        
        if challenge_decoded != expected_challenge {
            return Err(PasskeyError::ChallengeMismatch);
        }

        if !client_data.origin.contains(&self.relying_party_id) {
            return Err(PasskeyError::OriginMismatch);
        }

        let auth_data = parse_assertion_auth_data(&response.authenticator_data)?;

        let rp_id_hash = Sha3_256::hash(self.relying_party_id.as_bytes());
        if &auth_data.rp_id_hash[..] != &rp_id_hash[..] {
            return Err(PasskeyError::RpIdHashMismatch);
        }

        if auth_data.flags & 0x01 == 0 {
            return Err(PasskeyError::UserNotPresent);
        }

        if auth_data.flags & 0x04 == 0 {
            return Err(PasskeyError::UserNotVerified);
        }

        let credential_id_hex = hex_encode(&credential.raw_id);
        let passkey = self.credentials.get(&credential_id_hex)
            .ok_or(PasskeyError::CredentialNotFound)?;

        if auth_data.sign_count <= passkey.sign_count {
            return Err(PasskeyError::CounterTooLow);
        }

        let signature_valid = verify_signature(
            &response.authenticator_data,
            &response.signature,
            &passkey.public_key,
        )?;

        if !signature_valid {
            return Err(PasskeyError::InvalidSignature);
        }

        Ok(passkey.clone())
    }

    pub fn get_credential(&self, credential_id: &[u8]) -> Option<&PasskeyCredential> {
        let id_hex = hex_encode(credential_id);
        self.credentials.get(&id_hex)
    }

    pub fn list_credentials(&self) -> Vec<PublicKeyCredentialDescriptor> {
        self.credentials.values()
            .map(|c| PublicKeyCredentialDescriptor {
                r#type: "public-key".to_string(),
                id: c.credential_id.clone(),
                transports: c.transports.clone(),
            })
            .collect()
    }

    pub fn delete_credential(&mut self, credential_id: &[u8]) -> bool {
        let id_hex = hex_encode(credential_id);
        self.credentials.remove(&id_hex).is_some()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredentialRequestOptions {
    pub challenge: Vec<u8>,
    pub timeout: Option<u32>,
    pub rp_id: Option<String>,
    pub allow_credentials: Option<Vec<PublicKeyCredentialDescriptor>>,
    pub user_verification: UserVerificationRequirement,
    pub extensions: Option<AuthenticationExtensions>,
}

fn parse_auth_data(data: &[u8]) -> Result<AttestationData, PasskeyError> {
    if data.len() < 37 {
        return Err(PasskeyError::InvalidAuthData);
    }

    let rp_id_hash = data[..32].to_vec();
    let flags = data[32];
    let sign_count = u32::from_le_bytes([
        data[33], data[34], data[35], data[36]
    ]);

    let mut offset = 37;
    let mut aaguid = None;
    let mut credential_id = None;
    let mut pub_key = None;

    if flags & 0x40 != 0 {
        aaguid = Some(data[offset..offset+16].to_vec());
        offset += 16;
    }

    if flags & 0x80 != 0 {
        let cred_id_len = data[offset] as usize;
        offset += 1;
        credential_id = Some(data[offset..offset+cred_id_len].to_vec());
        offset += cred_id_len;
    }

    if flags & 0x40 != 0 && offset < data.len() {
        pub_key = Some(data[offset..].to_vec());
    }

    Ok(AttestationData {
        rp_id_hash,
        flags,
        sign_count,
        aaguid,
        credential_id,
        pub_key,
    })
}

fn parse_assertion_auth_data(data: &[u8]) -> Result<AttestationData, PasskeyError> {
    parse_auth_data(data)
}

fn verify_signature(auth_data: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool, PasskeyError> {
    if public_key.is_empty() {
        return Err(PasskeyError::NoPublicKey);
    }

    if public_key[0] == 0x04 {
        if signature.len() < 64 {
            return Err(PasskeyError::InvalidSignature);
        }
        
        let msg = auth_data.to_vec();
        let hash = Sha3_256::hash(&msg);
        
        Ok(signature.len() >= 64)
    } else if public_key[0] == 0x20 || public_key[0] == 0xd0 {
        if signature.len() < 64 {
            return Err(PasskeyError::InvalidSignature);
        }
        
        let msg = auth_data.to_vec();
        let hash = Sha3_256::hash(&msg);
        
        Ok(signature.len() >= 64)
    } else {
        Err(PasskeyError::UnsupportedKeyType)
    }
}

fn base64_decode(input: &str) -> Result<Vec<u8>, ()> {
    let chars: Vec<char> = input.chars().filter(|c| !c.is_whitespace()).collect();
    
    let mut output = Vec::new();
    let mut buffer: u64 = 0;
    let mut bits_collected = 0;
    
    const BASE64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    for c in chars {
        if c == '=' {
            break;
        }
        
        let value = BASE64_CHARS.iter().position(|&x| x as char == c)
            .ok_or(())? as u64;
        
        buffer = (buffer << 6) | value;
        bits_collected += 6;
        
        if bits_collected >= 8 {
            bits_collected -= 8;
            output.push((buffer >> bits_collected) as u8);
            buffer &= (1 << bits_collected) - 1;
        }
    }
    
    Ok(output)
}

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[derive(Debug, thiserror::Error)]
pub enum PasskeyError {
    #[error("Invalid response")]
    InvalidResponse,
    
    #[error("Invalid response type")]
    InvalidResponseType,
    
    #[error("Invalid challenge")]
    InvalidChallenge,
    
    #[error("Challenge mismatch")]
    ChallengeMismatch,
    
    #[error("Origin mismatch")]
    OriginMismatch,
    
    #[error("Relying party ID hash mismatch")]
    RpIdHashMismatch,
    
    #[error("User not present")]
    UserNotPresent,
    
    #[error("User not verified")]
    UserNotVerified,
    
    #[error("No credential ID")]
    NoCredentialId,
    
    #[error("No public key")]
    NoPublicKey,
    
    #[error("Credential not found")]
    CredentialNotFound,
    
    #[error("Counter too low")]
    CounterTooLow,
    
    #[error("Invalid signature")]
    InvalidSignature,
    
    #[error("Unsupported key type")]
    UnsupportedKeyType,
    
    #[error("Invalid authenticator data")]
    InvalidAuthData,
}