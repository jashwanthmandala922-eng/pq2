#![allow(unused_variables, dead_code)]
use zeroize::Zeroize;

const CHACHA_KEY_SIZE: usize = 32;
const CHACHA_NONCE_SIZE: usize = 12;
const CHACHA_BLOCK_SIZE: usize = 64;

pub struct ChaChaRng {
    state: [u32; 16],
    counter: u32,
}

impl ChaChaRng {
    pub fn new(seed: &[u8]) -> Self {
        let mut key = [0u32; 8];
        let mut seed_bytes = [0u8; CHACHA_KEY_SIZE];
        seed_bytes[..seed.len().min(CHACHA_KEY_SIZE)].copy_from_slice(&seed[..seed.len().min(CHACHA_KEY_SIZE)]);
        
        for i in 0..8 {
            key[i] = u32::from_le_bytes([
                seed_bytes[4*i],
                seed_bytes[4*i+1],
                seed_bytes[4*i+2],
                seed_bytes[4*i+3],
            ]);
        }
        
        let state = [
            0x61707865,
            0x3320646e,
            0x79622d32,
            0x6b206574,
            key[0], key[1], key[2], key[3],
            key[4], key[5], key[6], key[7],
            0, 0, 0, 0,
        ];
        
        Self { state, counter: 0 }
    }
    
    pub fn fill_bytes(&mut self, output: &mut [u8]) {
        let mut block = [0u8; CHACHA_BLOCK_SIZE];
        let mut working = self.state;
        working[12] = self.counter;
        
        let mut offset = 0;
        while offset < output.len() {
            chacha20_block(&mut block, &working);
            let len = CHACHA_BLOCK_SIZE.min(output.len() - offset);
            output[offset..offset+len].copy_from_slice(&block[..len]);
            offset += len;
            self.counter = self.counter.wrapping_add(1);
            working[12] = self.counter;
        }
    }
}

fn chacha20_block(output: &mut [u8; 64], state: &[u32; 16]) {
    let s = *state;
    let mut x = s;
    
    for _ in 0..10 {
        quarter_round(&mut x, 0, 4, 8, 12);
        quarter_round(&mut x, 1, 5, 9, 13);
        quarter_round(&mut x, 2, 6, 10, 14);
        quarter_round(&mut x, 3, 7, 11, 15);
        quarter_round(&mut x, 0, 5, 10, 15);
        quarter_round(&mut x, 1, 6, 11, 12);
        quarter_round(&mut x, 2, 7, 8, 13);
        quarter_round(&mut x, 3, 4, 9, 14);
    }
    
    for i in 0..16 {
        let le = (x[i].wrapping_add(s[i])).to_le_bytes();
        output[4*i..].copy_from_slice(&le);
    }
}

pub fn quarter_round(x: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    x[a] = x[a].wrapping_add(x[b]);
    x[d] ^= x[a];
    x[d] = x[d].rotate_left(16);
    x[c] = x[c].wrapping_add(x[d]);
    x[b] ^= x[c];
    x[b] = x[b].rotate_left(12);
    x[a] = x[a].wrapping_add(x[b]);
    x[d] ^= x[a];
    x[d] = x[d].rotate_left(8);
    x[c] = x[c].wrapping_add(x[d]);
    x[b] ^= x[c];
    x[b] = x[b].rotate_left(7);
}

impl Default for ChaChaRng {
    fn default() -> Self {
        Self::new(b"SecureVault-default!")
    }
}

impl Zeroize for ChaChaRng {
    fn zeroize(&mut self) {
        self.state = [0; 16];
        self.counter = 0;
    }
}