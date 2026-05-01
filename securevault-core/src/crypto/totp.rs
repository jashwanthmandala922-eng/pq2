use crate::crypto::Sha3_256;
use crate::crypto::rng::ChaChaRng;

const TOTP_STEP_SECONDS: u64 = 30;
const TOTP_DIGITS: usize = 6;
const TOTP_SECRET_SIZE: usize = 20;
const TOTP_WINDOW: usize = 1;

pub fn generate_totp_secret() -> [u8; TOTP_SECRET_SIZE] {
    let mut secret = [0u8; TOTP_SECRET_SIZE];
    let mut rng = ChaChaRng::new(b"SecureVault-TOTP-seed!");
    rng.fill_bytes(&mut secret);
    secret
}

pub struct TotpManager {
    secret: [u8; TOTP_SECRET_SIZE],
    issuer: String,
    account_name: String,
}

impl TotpManager {
    pub fn new(secret: [u8; TOTP_SECRET_SIZE], issuer: String, account_name: String) -> Self {
        Self {
            secret,
            issuer,
            account_name,
        }
    }

    pub fn generate_code(&self, timestamp: u64) -> String {
        let counter = timestamp / TOTP_STEP_SECONDS;
        self.generate_hotp(counter)
    }

    pub fn generate_current_code(&self) -> String {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.generate_code(timestamp)
    }

    fn generate_hotp(&self, counter: u64) -> String {
        let counter_bytes = counter.to_be_bytes();
        
        let hmac = self.compute_hmac(&counter_bytes);
        
        let offset = (hmac[hmac.len() - 1] & 0x0f) as usize;
        
        let truncated = ((hmac[offset] & 0x7f) as u32) << 24
            | (hmac[offset + 1] as u32) << 16
            | (hmac[offset + 2] as u32) << 8
            | (hmac[offset + 3] as u32);
        
        let otp = truncated % 10u32.pow(TOTP_DIGITS as u32);
        
        format!("{:0>width$}", otp, width = TOTP_DIGITS)
    }

    fn compute_hmac(&self, data: &[u8]) -> Vec<u8> {
        let mut key_block = [0x00u8; 64];
        
        if self.secret.len() > 64 {
            let hash = Sha3_256::hash(&self.secret);
            key_block[..32].copy_from_slice(&hash);
        } else {
            key_block[..self.secret.len()].copy_from_slice(&self.secret);
        }
        
        for (_i, byte) in key_block.iter_mut().enumerate() {
            *byte ^= 0x5c;
        }
        
        let inner_msg_len = 64 + data.len();
        let mut inner_msg = vec![0u8; inner_msg_len];
        
        let inner_key: Vec<u8> = (0..64)
            .map(|i| 0x36 ^ self.secret.get(i).copied().unwrap_or(0))
            .collect();
        
        for (i, &b) in inner_key.iter().enumerate() {
            inner_msg[i] = b;
        }
        inner_msg[64..].copy_from_slice(data);
        
        let inner_hash = Sha3_256::hash(&inner_msg);
        
        let mut outer_msg = Vec::with_capacity(64 + 32);
        outer_msg.extend_from_slice(&key_block);
        outer_msg.extend_from_slice(&inner_hash);
        
        Sha3_256::hash(&outer_msg).to_vec()
    }

    pub fn verify(&self, code: &str) -> bool {
        verify_totp_code(&self.secret, code)
    }

    pub fn get_otpauth_uri(&self) -> String {
        let secret_b32 = base32_encode(&self.secret);
        let label = format!("{}:{}", self.issuer, self.account_name);
        
        format!(
            "otpauth://totp/{}?secret={}&issuer={}&algorithm=SHA256&digits={}&period={}",
            urlencoding::encode(&label),
            secret_b32,
            urlencoding::encode(&self.issuer),
            TOTP_DIGITS,
            TOTP_STEP_SECONDS
        )
    }

    pub fn to_qr_data(&self) -> String {
        self.get_otpauth_uri()
    }
}

pub fn verify_totp_code(secret: &[u8; TOTP_SECRET_SIZE], code: &str) -> bool {
    if code.len() != TOTP_DIGITS {
        return false;
    }
    
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    let current_counter = now / TOTP_STEP_SECONDS;
    
    for i in 0..=TOTP_WINDOW {
        let counter = current_counter as u64 + i as u64;
        
        if let Some(expected) = compute_code_for_counter(secret, counter) {
            if constant_time_eq(code, &expected) {
                return true;
            }
        }
        
        if i > 0 {
            let counter = current_counter as u64 - i as u64;
            if let Some(expected) = compute_code_for_counter(secret, counter) {
                if constant_time_eq(code, &expected) {
                    return true;
                }
            }
        }
    }
    
    false
}

fn compute_code_for_counter(secret: &[u8; TOTP_SECRET_SIZE], counter: u64) -> Option<String> {
    let counter_bytes = counter.to_be_bytes();
    
    let mut key_block = [0x00u8; 64];
    if secret.len() > 64 {
        let hash = Sha3_256::hash(secret);
        key_block[..32].copy_from_slice(&hash);
    } else {
        key_block[..secret.len()].copy_from_slice(secret);
    }
    
    let inner_key: Vec<u8> = key_block.iter().map(|b| b ^ 0x36).collect();
    let mut inner_msg = inner_key.clone();
    inner_msg.extend_from_slice(&counter_bytes);
    let inner_hash = Sha3_256::hash(&inner_msg);
    
    let outer_key: Vec<u8> = key_block.iter().map(|b| b ^ 0x5c).collect();
    let mut outer_msg = outer_key;
    outer_msg.extend_from_slice(&inner_hash);
    let hmac = Sha3_256::hash(&outer_msg);
    
    let offset = (hmac[hmac.len() - 1] & 0x0f) as usize;
    
    let truncated = ((hmac[offset] & 0x7f) as u32) << 24
        | (hmac[offset + 1] as u32) << 16
        | (hmac[offset + 2] as u32) << 8
        | (hmac[offset + 3] as u32);
    
    let otp = truncated % 10u32.pow(TOTP_DIGITS as u32);
    
    Some(format!("{:0>width$}", otp, width = TOTP_DIGITS))
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    let a = a.as_bytes();
    let b = b.as_bytes();
    
    let mut result = 0u8;
    for i in 0..a.len() {
        result |= a[i] ^ b[i];
    }
    
    result == 0
}

fn base32_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    
    let mut result = String::new();
    let mut buffer = 0u32;
    let mut bits_left = 0;
    
    for byte in data {
        buffer = (buffer << 8) | (*byte as u32);
        bits_left += 8;
        
        while bits_left >= 5 {
            bits_left -= 5;
            let index = ((buffer >> bits_left) & 0x1f) as usize;
            result.push(ALPHABET[index] as char);
        }
    }
    
    if bits_left > 0 {
        let index = ((buffer << (5 - bits_left)) & 0x1f) as usize;
        result.push(ALPHABET[index] as char);
    }
    
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_totp_generation() {
        let secret = generate_totp_secret();
        let manager = TotpManager::new(secret, "SecureVault".to_string(), "test@example.com".to_string());
        
        let code = manager.generate_current_code();
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }
    
    #[test]
    fn test_totp_verification() {
        let secret = generate_totp_secret();
        let manager = TotpManager::new(secret, "SecureVault".to_string(), "test@example.com".to_string());
        
        let code = manager.generate_current_code();
        assert!(manager.verify(&code));
    }
    
    #[test]
    fn test_totp_invalid_code() {
        let secret = generate_totp_secret();
        let manager = TotpManager::new(secret, "SecureVault".to_string(), "test@example.com".to_string());
        
        assert!(!manager.verify("000000"));
    }
}