#![allow(unused_variables, dead_code)]
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use zeroize::Zeroize;

use crate::crypto::{Sha3_256, ChaChaRng, argon2id_hash, quarter_round};
use crate::crypto::hybrid::HybridCiphertext;

const SALT_SIZE: usize = 32;
const KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;

#[derive(Clone, Debug)]
pub struct SensitiveString(String);

impl SensitiveString {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl Zeroize for SensitiveString {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for SensitiveString {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Serialize for SensitiveString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SensitiveString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(Self(s))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordEntry {
    pub id: String,
    pub title: String,
    pub username: Option<String>,
    #[serde(skip_serializing)]
    pub password: SensitiveString,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub category: Option<String>,
    #[serde(with = "chrono::serde::ts_seconds")]
    pub created: DateTime<Utc>,
    #[serde(with = "chrono::serde::ts_seconds")]
    pub modified: DateTime<Utc>,
    pub last_used: Option<DateTime<Utc>>,
    pub use_count: u32,
    pub favorite: bool,
}

impl PasswordEntry {
    pub fn new(title: String, password: impl Into<String>) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            title,
            username: None,
            password: SensitiveString::new(password),
            url: None,
            notes: None,
            category: None,
            created: now,
            modified: now,
            last_used: None,
            use_count: 0,
            favorite: false,
        }
    }

    pub fn get_password(&self) -> &str {
        self.password.as_str()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedEntry {
    pub id: String,
    pub encapsulated_key: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; NONCE_SIZE],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vault {
    pub entries: Vec<EncryptedEntry>,
    pub version: u32,
    pub created: DateTime<Utc>,
    pub modified: DateTime<Utc>,
}

impl Vault {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            version: 1,
            created: Utc::now(),
            modified: Utc::now(),
        }
    }
}

impl Default for Vault {
    fn default() -> Self {
        Self::new()
    }
}

pub struct SecureVault {
    master_key: [u8; 64],
    vault: Vault,
}

impl SecureVault {
    pub fn create(master_password: &str) -> Self {
        let mut salt = [0u8; SALT_SIZE];
        ChaChaRng::new(master_password.as_bytes()).fill_bytes(&mut salt);

        let key = derive_key(master_password, &salt);
        
        let vault = Vault::new();
        
        Self {
            master_key: key,
            vault,
        }
    }

    pub fn open(master_password: &str, encrypted_vault: &[u8]) -> Result<Self, VaultError> {
        let min_len = SALT_SIZE + std::mem::size_of::<HybridCiphertext>();
        if encrypted_vault.len() < min_len {
            return Err(VaultError::InvalidData);
        }

        let salt: [u8; SALT_SIZE] = encrypted_vault[..SALT_SIZE].try_into().unwrap();
        let key = derive_key(master_password, &salt);

        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&key[..NONCE_SIZE]);

        let hybrid_ct_len = std::mem::size_of::<HybridCiphertext>();
        let ct_data = &encrypted_vault[SALT_SIZE..SALT_SIZE + hybrid_ct_len];
        let ciphertext = &encrypted_vault[SALT_SIZE + hybrid_ct_len..];

        let mut cipher_data = Vec::with_capacity(hybrid_ct_len + ciphertext.len());
        cipher_data.extend_from_slice(ct_data);
        cipher_data.extend_from_slice(ciphertext);

        let decrypted = hybrid_decrypt(&key[32..], &cipher_data)?;
        
        let vault: Vault = serde_json::from_slice(&decrypted)
            .map_err(|_| VaultError::InvalidPassword)?;

        Ok(Self {
            master_key: key,
            vault,
        })
    }

    pub fn add_entry(&mut self, entry: PasswordEntry) -> Result<EncryptedEntry, VaultError> {
        let plaintext = serde_json::to_vec(&entry)
            .map_err(|_| VaultError::SerializationError)?;

        let mut nonce = [0u8; NONCE_SIZE];
        ChaChaRng::new(&self.master_key).fill_bytes(&mut nonce);

        let (ciphertext, encapsulated) = hybrid_encrypt(&self.master_key[32..], &plaintext, &nonce)?;
        
        let enc_entry = EncryptedEntry {
            id: entry.id,
            encapsulated_key: encapsulated,
            ciphertext,
            nonce,
        };

        self.vault.entries.push(enc_entry.clone());
        self.vault.modified = Utc::now();

        Ok(enc_entry)
    }

    pub fn get_entry(&self, id: &str) -> Result<PasswordEntry, VaultError> {
        let enc_entry = self.vault.entries
            .iter()
            .find(|e| e.id == id)
            .ok_or(VaultError::EntryNotFound)?;

        let plaintext = hybrid_decrypt(&self.master_key[32..], &enc_entry.ciphertext)?;
        
        let entry: PasswordEntry = serde_json::from_slice(&plaintext)
            .map_err(|_| VaultError::DeserializationError)?;

        Ok(entry)
    }

    pub fn update_entry(&mut self, entry: PasswordEntry) -> Result<(), VaultError> {
        let idx = self.vault.entries
            .iter()
            .position(|e| e.id == entry.id)
            .ok_or(VaultError::EntryNotFound)?;

        let plaintext = serde_json::to_vec(&entry)
            .map_err(|_| VaultError::SerializationError)?;

        let mut nonce = [0u8; NONCE_SIZE];
        ChaChaRng::new(&self.master_key).fill_bytes(&mut nonce);

        let (ciphertext, encapsulated) = hybrid_encrypt(&self.master_key[32..], &plaintext, &nonce)?;
        
        self.vault.entries[idx] = EncryptedEntry {
            id: entry.id,
            encapsulated_key: encapsulated,
            ciphertext,
            nonce,
        };

        self.vault.modified = Utc::now();

        Ok(())
    }

    pub fn delete_entry(&mut self, id: &str) -> Result<(), VaultError> {
        let idx = self.vault.entries
            .iter()
            .position(|e| e.id == id)
            .ok_or(VaultError::EntryNotFound)?;

        self.vault.entries.remove(idx);
        self.vault.modified = Utc::now();

        Ok(())
    }

    pub fn list_entries(&self) -> Vec<String> {
        self.vault.entries.iter().map(|e| e.id.clone()).collect()
    }

    pub fn export_encrypted(&self) -> Vec<u8> {
        let plaintext = serde_json::to_vec(&self.vault).unwrap();
        
        let salt = {
            let mut s = [0u8; SALT_SIZE];
            ChaChaRng::new(b"SecureVault-salt!").fill_bytes(&mut s);
            s
        };
        
        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&self.master_key[..NONCE_SIZE]);
        
        let (encrypted, encapsulated) = hybrid_encrypt(&self.master_key[32..], &plaintext, &nonce).unwrap();
        
        let hybrid_ct_len = std::mem::size_of::<HybridCiphertext>();
        let mut result = Vec::with_capacity(SALT_SIZE + hybrid_ct_len + encrypted.len());
        result.extend_from_slice(&salt);
        
        let mut hybrid_bytes = Vec::with_capacity(hybrid_ct_len);
        let ct_bytes = encapsulated.as_ref();
        hybrid_bytes.extend_from_slice(ct_bytes);
        result.extend_from_slice(&hybrid_bytes);
        result.extend_from_slice(&encrypted);
        
        result
    }
}

impl Drop for SecureVault {
    fn drop(&mut self) {
        self.master_key.zeroize();
    }
}

fn derive_key(password: &str, salt: &[u8; SALT_SIZE]) -> [u8; 64] {
    let key = argon2id_hash(password.as_bytes(), salt);
    
    let mut output = [0u8; 64];
    output[..32].copy_from_slice(&key);
    output[32..].copy_from_slice(&key);
    
    output
}

fn hybrid_encrypt(key: &[u8], plaintext: &[u8], nonce: &[u8; NONCE_SIZE]) -> Result<(Vec<u8>, Vec<u8>), VaultError> {
    let (pk, _sk): (Vec<u8>, Vec<u8>) = crate::crypto::ml_kem::Kyber768Engine::keygen(None);
    let pk_ref: &[u8] = pk.as_ref();
    let pk_array: &[u8; 1184] = pk_ref.try_into().map_err(|_| VaultError::InvalidData)?;
    let (ciphertext, shared_secret) = crate::crypto::ml_kem::Kyber768Engine::encaps(pk_array);
    
    let mut sealing_key = [0u8; 32];
    for i in 0..32 {
        sealing_key[i] = key[i] ^ shared_secret[i];
    }
    
    let mut output = Vec::with_capacity(NONCE_SIZE + 16 + plaintext.len());
    output.extend_from_slice(nonce);
    
    let mut data_to_encrypt = plaintext.to_vec();
    aes_gcm_encrypt(&sealing_key, nonce, &mut data_to_encrypt);
    output.extend_from_slice(&data_to_encrypt);
    
    Ok((output, ciphertext))
}

fn hybrid_decrypt(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, VaultError> {
    let encap_len = 1088;
    if ciphertext.len() < encap_len + NONCE_SIZE {
        return Err(VaultError::InvalidData);
    }
    
    let encapsulated = &ciphertext[..encap_len];
    let encrypted_data = &ciphertext[encap_len + NONCE_SIZE..];
    
    let sk_array: &[u8; 2400] = &[0u8; 2400];
    let shared_secret = crate::crypto::ml_kem::Kyber768Engine::decaps(sk_array, encapsulated);
    
    let mut sealing_key = [0u8; 32];
    for i in 0..32 {
        sealing_key[i] = key[i] ^ shared_secret[i];
    }
    
    let nonce: &[u8; NONCE_SIZE] = ciphertext[encap_len..encap_len + NONCE_SIZE].try_into().unwrap();
    let mut decrypted = encrypted_data.to_vec();
    decrypted = aes_gcm_decrypt(&sealing_key, nonce, decrypted)?;
    
    Ok(decrypted)
}

fn aes_gcm_encrypt(key: &[u8], nonce: &[u8; NONCE_SIZE], data: &mut Vec<u8>) {
    let key_array: [u32; 4] = [
        u32::from_le_bytes([key[0], key[1], key[2], key[3]]),
        u32::from_le_bytes([key[4], key[5], key[6], key[7]]),
        u32::from_le_bytes([key[8], key[9], key[10], key[11]]),
        u32::from_le_bytes([key[12], key[13], key[14], key[15]]),
    ];
    
    let nonce_u32: [u32; 3] = [
        u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]),
        u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]),
        u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]),
    ];
    
    let full_nonce = [
        nonce_u32[0], nonce_u32[1], nonce_u32[2], 0u32,
        key_array[0] ^ key_array[1],
        key_array[2] ^ key_array[3],
        key_array[0] ^ key_array[2],
        key_array[1] ^ key_array[3],
    ];
    
    let mut block_count = (data.len() + 16 - 1) / 16;
    if block_count == 0 { block_count = 1; }
    
    let mut j = 0;
    for chunk in data.chunks_mut(16) {
        let mut counter_block = full_nonce;
        counter_block[3] = j as u32;
        
        let mut keystream = [0u8; 16];
        chacha20_block(&mut keystream, &counter_block, &key_array);
        
        for (i, byte) in chunk.iter_mut().enumerate() {
            *byte ^= keystream[i];
        }
        
        j += 1;
    }
    
    let mut tag_input = data.to_vec();
    tag_input.extend_from_slice(nonce);
    tag_input.extend_from_slice(&(data.len() as u64).to_le_bytes());
    
    let tag = Sha3_256::hash(&tag_input);
    data.extend_from_slice(&tag[..16]);
}

fn aes_gcm_decrypt(key: &[u8], nonce: &[u8; NONCE_SIZE], mut data: Vec<u8>) -> Result<Vec<u8>, VaultError> {
    let data_len = data.len() - 16;
    let (ct_part, tag_part) = data.split_at_mut(data_len);
    let ciphertext = ct_part;
    let received_tag = tag_part.to_vec();
    
    let key_array: [u32; 4] = [
        u32::from_le_bytes([key[0], key[1], key[2], key[3]]),
        u32::from_le_bytes([key[4], key[5], key[6], key[7]]),
        u32::from_le_bytes([key[8], key[9], key[10], key[11]]),
        u32::from_le_bytes([key[12], key[13], key[14], key[15]]),
    ];
    
    let nonce_u32: [u32; 3] = [
        u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]),
        u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]),
        u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]),
    ];
    
    let full_nonce = [
        nonce_u32[0], nonce_u32[1], nonce_u32[2], 0u32,
        key_array[0] ^ key_array[1],
        key_array[2] ^ key_array[3],
        key_array[0] ^ key_array[2],
        key_array[1] ^ key_array[3],
    ];
    
    let mut j = 0;
    for chunk in ciphertext.chunks_mut(16) {
        let mut counter_block = full_nonce;
        counter_block[3] = j as u32;
        
        let mut keystream = [0u8; 16];
        chacha20_block(&mut keystream, &counter_block, &key_array);
        
        for (i, byte) in chunk.iter_mut().enumerate() {
            *byte ^= keystream[i];
        }
        
        j += 1;
    }
    
    let mut tag_input = ciphertext.to_vec();
    tag_input.extend_from_slice(nonce);
    tag_input.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    
    let computed_tag = Sha3_256::hash(&tag_input);
    if computed_tag[..16] != received_tag[..] {
        return Err(VaultError::AuthenticationFailed);
    }
    
    data.truncate(data_len);
    
    Ok(data)
}

fn chacha20_block(output: &mut [u8; 16], nonce: &[u32; 8], key: &[u32; 4]) {
    let mut state = [
        0x61707865u32, 0x3320646eu32, 0x79622d32u32, 0x6b206574u32,
        key[0], key[1], key[2], key[3],
        nonce[0], nonce[1], nonce[2], nonce[3],
        nonce[4] ^ 0x4a5a5a5a, nonce[5] ^ 0x5a5a5a5a, nonce[6] ^ 0x6a6a6a6a, nonce[7] ^ 0x7a7a7a7a,
    ];
    
    for _ in 0..10 {
        quarter_round(&mut state, 0, 4, 8, 12);
        quarter_round(&mut state, 1, 5, 9, 13);
        quarter_round(&mut state, 2, 6, 10, 14);
        quarter_round(&mut state, 3, 7, 11, 15);
        quarter_round(&mut state, 0, 5, 10, 15);
        quarter_round(&mut state, 1, 6, 11, 12);
        quarter_round(&mut state, 2, 7, 8, 13);
        quarter_round(&mut state, 3, 4, 9, 14);
    }
    
    for i in 0..4 {
        let le = state[i].to_le_bytes();
        output[4 * i] = le[0];
        output[4 * i + 1] = le[1];
        output[4 * i + 2] = le[2];
        output[4 * i + 3] = le[3];
    }
}

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("Invalid password")]
    InvalidPassword,
    
    #[error("Entry not found")]
    EntryNotFound,
    
    #[error("Invalid data")]
    InvalidData,
    
    #[error("Authentication failed")]
    AuthenticationFailed,
    
    #[error("Serialization error")]
    SerializationError,
    
    #[error("Deserialization error")]
    DeserializationError,
}