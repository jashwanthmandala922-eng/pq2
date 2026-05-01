#![allow(unused_variables, dead_code)]
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Serialize, Deserialize)]
pub struct HybridKeyPair {
    pub classical: ClassicalKeyPair,
    pub quantum: QuantumKeyPair,
    pub shared_secret: Option<SharedSecret>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ClassicalKeyPair {
    pub public_key: [u8; 32],
    pub secret_key: [u8; 32],
}

#[derive(Clone, Serialize, Deserialize)]
pub struct QuantumKeyPair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

#[derive(Clone, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct SharedSecret {
    pub classical: Vec<u8>,
    pub quantum: Vec<u8>,
    pub combined: Vec<u8>,
}

impl HybridKeyPair {
    pub fn generate() -> Self {
        let classical = ClassicalKeyPair::generate();
        let classical_shared_bytes = classical.shared_bytes();
        
        let (quantum_pk, quantum_sk): (Vec<u8>, Vec<u8>) = crate::crypto::ml_kem::Kyber768Engine::keygen(None);
        let quantum_ct;
        let quantum_shared;
        {
            let pk_ref = quantum_pk.as_slice();
            let mut pk_arr = [0u8; 1184];
            pk_arr.copy_from_slice(pk_ref);
            let (ct, qs) = crate::crypto::ml_kem::Kyber768Engine::encaps(&pk_arr);
            quantum_ct = ct;
            quantum_shared = qs;
        }
        
        let mut combined = vec![0u8; 64];
        combined[..32].copy_from_slice(classical_shared_bytes.as_ref());
        combined[32..].copy_from_slice(&quantum_shared);
        
        Self {
            classical,
            quantum: QuantumKeyPair {
                public_key: quantum_pk,
                secret_key: quantum_sk,
            },
            shared_secret: Some(SharedSecret {
                classical: classical_shared_bytes.to_vec(),
                quantum: quantum_shared.to_vec(),
                combined,
            }),
        }
    }
    
    pub fn encapsulate(public_key: &HybridPublicKey) -> HybridCiphertext {
        let classical_ct = classical_encapsulate(&public_key.classical);
        
        let pk_ref = public_key.quantum.as_slice();
        let mut pk_arr = [0u8; 1184];
        pk_arr.copy_from_slice(pk_ref);
        let (quantum_ct, quantum_shared) = crate::crypto::ml_kem::Kyber768Engine::encaps(&pk_arr);
        
        let mut combined_key = vec![0u8; 64];
        combined_key[..32].copy_from_slice(classical_shared_kdf(&classical_ct).as_ref());
        combined_key[32..].copy_from_slice(&quantum_shared);
        
        HybridCiphertext {
            classical: classical_ct.to_vec(),
            quantum: quantum_ct,
            combined_key,
        }
    }
    
    pub fn decrypt(&self, ciphertext: &HybridCiphertext) -> SharedSecret {
        let ct_ref = ciphertext.classical.as_slice();
        let mut ct_arr = [0u8; 32];
        ct_arr.copy_from_slice(ct_ref);
        let classical_shared = classical_decapsulate(&self.classical.secret_key, &ct_arr);

        let sk_ref = self.quantum.secret_key.as_slice();
        let mut sk_arr = [0u8; 2400];
        sk_arr.copy_from_slice(sk_ref);
        let quantum_shared = crate::crypto::ml_kem::Kyber768Engine::decaps(&sk_arr, &ciphertext.quantum);
        
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(&classical_shared);
        combined[32..].copy_from_slice(&quantum_shared);
        
        SharedSecret {
            classical: classical_shared.to_vec(),
            quantum: quantum_shared.to_vec(),
            combined: combined.to_vec(),
        }
    }
}

impl ClassicalKeyPair {
    pub fn generate() -> Self {
        let mut secret_key = [0u8; 32];
        let mut public_key = [0u8; 32];
        
        x25519_keygen(&mut secret_key, &mut public_key);
        
        Self { public_key, secret_key }
    }
    
    pub fn shared_bytes(&self) -> [u8; 32] {
        let mut shared = [0u8; 32];
        x25519_scalarmult(&self.secret_key, &self.public_key, &mut shared);
        shared
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct HybridPublicKey {
    pub classical: [u8; 32],
    pub quantum: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct HybridCiphertext {
    pub classical: Vec<u8>,
    pub quantum: Vec<u8>,
    pub combined_key: Vec<u8>,
}

fn x25519_keygen(secret: &mut [u8; 32], public: &mut [u8; 32]) {
    use crate::crypto::ChaChaRng;
    
    let mut rng = ChaChaRng::new(b"SecureVault-X25519!");
    rng.fill_bytes(secret);
    
    secret[0] &= 248;
    secret[31] &= 127;
    secret[31] |= 64;
    
    curve25519_scalar_mult(secret, public);
}

fn curve25519_scalar_mult(scalar: &[u8; 32], result: &mut [u8; 32]) {
    let mut e = *scalar;
    e[0] &= 248;
    e[31] &= 127;
    e[31] |= 64;
    
    let x_1: u64 = 1;
    let mut x_2: u64 = 0;
    let _x_3: u64 = 0;
    let z_1: u64 = 0;
    let mut z_2: u64 = 1;
    
    let mut pos = 1;
    let mut b = e[pos];
    
    for _i in (0..255).rev() {
        while pos < 32 && b == 0 {
            b = e[pos];
            pos += 1;
        }
        
        let bit = (b >> 7) & 1;
        b <<= 1;
        
        x_2 = x_2 ^ ((x_1 * bit as u64));
        z_2 = z_2 ^ ((z_1 * bit as u64));
    }
    
    result[0] = (x_2 & 0xFF) as u8;
}

fn classical_encapsulate(public_key: &[u8; 32]) -> [u8; 32] {
    let mut ephemeral_sk = [0u8; 32];
    let mut ephemeral_pk = [0u8; 32];
    
    x25519_keygen(&mut ephemeral_sk, &mut ephemeral_pk);
    
    let mut shared = [0u8; 32];
    x25519_scalarmult(&ephemeral_sk, public_key, &mut shared);
    
    shared
}

fn classical_decapsulate(secret_key: &[u8; 32], ciphertext: &[u8; 32]) -> [u8; 32] {
    let mut shared = [0u8; 32];
    x25519_scalarmult(secret_key, ciphertext, &mut shared);
    shared
}

fn classical_shared_kdf(shared_secret: &[u8; 32]) -> [u8; 32] {
    use crate::crypto::Sha3_256;
    
    let mut input = vec![0u8; 32 + 16];
    input[..32].copy_from_slice(shared_secret);
    input[32..].copy_from_slice(b"classical-kdf");
    
    let hash = Sha3_256::hash(&input);
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash);
    result
}

fn x25519_scalarmult(scalar: &[u8; 32], _point: &[u8; 32], result: &mut [u8; 32]) {
    curve25519_scalar_mult(scalar, result);
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_hybrid_keypair() {
        let alice = HybridKeyPair::generate();
        let bob_pub = HybridPublicKey {
            classical: alice.classical.public_key,
            quantum: alice.quantum.public_key.clone(),
        };
        
        let ciphertext = HybridKeyPair::encapsulate(&bob_pub);
        let _shared = alice.decrypt(&ciphertext);
    }
}