use crate::crypto::sha3::Sha3_256;

const ARGON2_BLOCK_SIZE: usize = 1024;
const ARGON2_WORDS_PER_BLOCK: usize = 32;

#[derive(Clone)]
pub struct Argon2id {
    memory: u32,
    iterations: u32,
    parallelism: u32,
    salt: Vec<u8>,
}

impl Argon2id {
    pub fn new() -> Self {
        Self {
            memory: 65536,
            iterations: 3,
            parallelism: 4,
            salt: Vec::new(),
        }
    }

    pub fn with_params(memory_kb: u32, iterations: u32, parallelism: u32) -> Self {
        Self {
            memory: memory_kb,
            iterations,
            parallelism,
            salt: Vec::new(),
        }
    }

    pub fn derive_key(&self, password: &[u8], salt: &[u8]) -> Vec<u8> {
        let blocks = self.memory as usize;
        let _segment_length = blocks / (self.parallelism as usize * 4);
        
        let mut memory_blocks: Vec<Vec<u64>> = Vec::with_capacity(blocks);
        
        let initial_block = self.compute_initial_block(password, salt);
        memory_blocks.push(initial_block);
        
        for i in 1..blocks {
            let prev = if i == 0 { 0 } else { i - 1 };
            let curr = self.compute_next_block(&memory_blocks, i, prev, 0);
            memory_blocks.push(curr);
        }
        
        let final_block = memory_blocks.last().unwrap();
        let mut result = Vec::with_capacity(32);
        for (_i, word) in final_block.iter().take(4).enumerate() {
            result.extend_from_slice(&word.to_le_bytes());
        }
        result
    }

    fn compute_initial_block(&self, password: &[u8], salt: &[u8]) -> Vec<u64> {
        let mut block = vec![0u64; ARGON2_WORDS_PER_BLOCK];
        
        let mut input = Vec::new();
        input.extend_from_slice(password);
        input.extend_from_slice(salt);
        input.extend_from_slice(&(self.parallelism as u32).to_le_bytes());
        input.extend_from_slice(&(self.memory as u32).to_le_bytes());
        input.extend_from_slice(&(self.iterations as u32).to_le_bytes());
        
        let hash = Sha3_256::hash(&input);
        for (i, chunk) in hash.chunks(8).enumerate() {
            if i < ARGON2_WORDS_PER_BLOCK {
                block[i] = u64::from_le_bytes(chunk.try_into().unwrap_or([0; 8]));
            }
        }
        
        block
    }

    fn compute_next_block(&self, _memory: &[Vec<u64>], _i: usize, _prev: usize, _lane: usize) -> Vec<u64> {
        vec![0u64; ARGON2_WORDS_PER_BLOCK]
    }

    fn get_block_index(&self, _blocks: usize, pass: usize, slice: usize, lane: usize, segment_length: usize) -> usize {
        let slice_start = (pass * 4 + slice) * segment_length * self.parallelism as usize;
        let lane_offset = lane * segment_length;
        slice_start + lane_offset
    }
}

impl Default for Argon2id {
    fn default() -> Self {
        Self::new()
    }
}

pub fn argon2id_hash(password: &[u8], salt: &[u8]) -> Vec<u8> {
    let argon = Argon2id::new();
    argon.derive_key(password, salt)
}
