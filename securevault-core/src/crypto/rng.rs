use zeroize::Zeroize;

const CHACHA_KEY_SIZE: usize = 32;
const CHACHA_NONCE_SIZE: usize = 12;
const CHACHA_BLOCK_SIZE: usize = 64;

pub struct ChaChaRng {
    state: [u32; 16],
    nonce: [u8; 12],
    position: usize,
}

impl ChaChaRng {
    pub fn new(seed: &[u8]) -> Self {
        let mut key = [0u8; 32];
        for i in 0..seed.len().min(32) {
            key[i] = seed[i];
        }

        let mut state = [0u32; 16];
        
        let constants = [
            0x61707865u32, 0x3320646eu32, 0x79622d32u32, 0x6b206574u32,
        ];
        
        state[0] = constants[0];
        state[1] = constants[1];
        state[2] = constants[2];
        state[3] = constants[3];

        for i in 0..8 {
            let key_word = key[4 * i..4 * (i + 1)].as_ptr() as *const u32;
            state[4 + i] = u32::from_le(*key_word);
        }

        Self {
            state,
            nonce: [0u8; 12],
            position: 0,
        }
    }

    pub fn fill_bytes(&mut self, output: &mut [u8]) {
        let mut chunk = [0u8; CHACHA_BLOCK_SIZE];
        
        for chunk_start in (0..output.len()).step_by(CHACHA_BLOCK_SIZE) {
            self.chacha20_block(&mut chunk);
            
            let chunk_end = (chunk_start + CHACHA_BLOCK_SIZE).min(output.len());
            for (i, &b) in chunk.iter().enumerate() {
                if chunk_start + i < output.len() {
                    output[chunk_start + i] ^= b;
                }
            }
        }
    }

    fn chacha20_block(&mut self, output: &mut [u8; CHACHA_BLOCK_SIZE]) {
        let mut working_state = self.state;

        for _ in 0..10 {
            self.quarter_round(&mut working_state, 0, 4, 8, 12);
            self.quarter_round(&mut working_state, 1, 5, 9, 13);
            self.quarter_round(&mut working_state, 2, 6, 10, 14);
            self.quarter_round(&mut working_state, 3, 7, 11, 15);
            self.quarter_round(&mut working_state, 0, 5, 10, 15);
            self.quarter_round(&mut working_state, 1, 6, 11, 12);
            self.quarter_round(&mut working_state, 2, 7, 8, 13);
            self.quarter_round(&mut working_state, 3, 4, 9, 14);
        }

        for i in 0..16 {
            let le_val = working_state[i].to_le_bytes();
            let out_idx = i * 4;
            output[out_idx] = le_val[0];
            output[out_idx + 1] = le_val[1];
            output[out_idx + 2] = le_val[2];
            output[out_idx + 3] = le_val[3];
        }

        for i in 0..16 {
            let sum = self.state[i].wrapping_add(working_state[i]);
            let le_bytes = sum.to_le_bytes();
            output[4 * i] = le_bytes[0];
            output[4 * i + 1] = le_bytes[1];
            output[4 * i + 2] = le_bytes[2];
            output[4 * i + 3] = le_bytes[3];
        }

        self.state[12] = self.state[12].wrapping_add(1);
        if self.state[12] == 0 {
            self.state[13] = self.state[13].wrapping_add(1);
        }
    }

    #[inline]
    fn quarter_round(&mut self, state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
        state[a] = state[a].wrapping_add(state[b]);
        state[d] ^= state[a];
        state[d] = state[d].rotate_left(16);
        
        state[c] = state[c].wrapping_add(state[d]);
        state[b] ^= state[c];
        state[b] = state[b].rotate_left(12);
        
        state[a] = state[a].wrapping_add(state[b]);
        state[d] ^= state[a];
        state[d] = state[d].rotate_left(8);
        
        state[c] = state[c].wrapping_add(state[d]);
        state[b] ^= state[c];
        state[b] = state[b].rotate_left(7);
    }
}

impl Default for ChaChaRng {
    fn default() -> Self {
        Self::new(b"SecureVault-DefaultRNG!")
    }
}

#[derive(Clone, Zeroize)]
pub struct SecureBuffer {
    data: Vec<u8>,
}

impl SecureBuffer {
    pub fn new(size: usize) -> Self {
        Self {
            data: vec![0u8; size],
        }
    }

    pub fn from_slice(slice: &[u8]) -> Self {
        Self {
            data: slice.to_vec(),
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}