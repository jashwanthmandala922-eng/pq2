use zeroize::Zeroize;
use crate::rng::ChaChaRng;
use crate::crypto::sha3::Sha3_256;

const ARGON2_BLOCK_SIZE: usize = 1024;
const ARGON2_WORDS_PER_BLOCK: usize = 32;

#[derive(Clone)]
pub struct Argon2id {
    memory: u32,
    iterations: u32,
    parallelism: u32,
    salt_len: u32,
    key_len: u32,
}

impl Argon2id {
    pub fn new() -> Self {
        Self {
            memory: 65536,
            iterations: 3,
            parallelism: 4,
            salt_len: 16,
            key_len: 32,
        }
    }

    pub fn with_params(memory_kb: u32, iterations: u32, parallelism: u32) -> Self {
        Self {
            memory: memory_kb,
            iterations,
            parallelism,
            salt_len: 16,
            key_len: 32,
        }
    }

    pub fn derive_key(&self, password: &[u8], salt: &[u8]) -> Vec<u8> {
        let blocks = self.memory as usize;
        let segment_length = blocks / (self.parallelism as usize * 4);
        
        let mut memory_blocks: Vec<[[u64; ARGON2_WORDS_PER_BLOCK]> > = Vec::with_capacity(blocks);
        
        let mut initial_block = self.compute_initial_block(password, salt);
        memory_blocks.push(initial_block);
        
        for i in 1..blocks {
            let prev = if i == 0 { 0 } else { i - 1 };
            let curr = self.compute_next_block(&memory_blocks, i, prev, 0);
            memory_blocks.push(curr);
        }
        
        for pass in 0..self.iterations as usize {
            for slice in 0..4 {
                for lane in 0..self.parallelism as usize {
                    let block_idx = self.get_block_index(blocks, pass, slice, lane, segment_length);
                    let prev_idx = if block_idx == 0 { 0 } else { block_idx - 1 };
                    
                    let curr_block = self.compute_next_block(&memory_blocks, block_idx, prev_idx, lane);
                    memory_blocks[block_idx] = curr_block;
                }
            }
        }
        
        let final_block = &memory_blocks[blocks - 1];
        let mut output = Vec::with_capacity(self.key_len as usize);
        
        for i in 0..(self.key_len as usize / 8) {
            let words = final_block[i];
            output.extend_from_slice(&words.to_le_bytes());
        }
        
        for block in memory_blocks.iter() {
            drop(*block);
        }
        memory_blocks.zeroize();
        
        output
    }

    fn compute_initial_block(&self, password: &[u8], salt: &[u8]) -> [[u64; ARGON2_WORDS_PER_BLOCK]; 1] {
        let mut block = [[0u64; ARGON2_WORDS_PER_BLOCK]];
        
        let mut input = Vec::with_capacity(
            password.len() + salt.len() + 
            4 + 4 + 4 + 4 + 4 + 1
        );
        
        input.extend_from_slice(password);
        input.extend_from_slice(salt);
        input.extend_from_slice(&self.memory.to_le_bytes());
        input.extend_from_slice(&self.iterations.to_le_bytes());
        input.extend_from_slice(&self.parallelism.to_le_bytes());
        input.extend_from_slice(&1u32.to_le_bytes());
        input.extend_from_slice(&0u8.to_le_bytes());
        
        let hash = Sha3_256::hash(&input);
        
        for (i, chunk) in hash.chunks(8).enumerate() {
            if i < ARGON2_WORDS_PER_BLOCK {
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(chunk);
                block[0][i] = u64::from_le_bytes(bytes);
            }
        }
        
        block[0][0] ^= (self.memory as u64).wrapping_sub(1);
        block[0][1] ^= self.iterations as u64;
        block[0][2] ^= self.parallelism as u64;
        
        block
    }

    fn compute_next_block(
        &self,
        memory: &[[[u64; ARGON2_WORDS_PER_BLOCK]]],
        curr_idx: usize,
        prev_idx: usize,
        lane: usize,
    ) -> [[u64; ARGON2_WORDS_PER_BLOCK]] {
        let mut result = [[0u64; ARGON2_WORDS_PER_BLOCK]];
        
        let prev_block = &memory[prev_idx % memory.len()];
        
        let ref_index = self.compute_ref_index(curr_idx, prev_block, lane);
        let ref_block = &memory[ref_index % memory.len()];
        
        let mut gamma = 0u64;
        for word in prev_block[0].iter() {
            gamma = gamma.wrapping_add(*word);
        }
        
        for i in 0..ARGON2_WORDS_PER_BLOCK {
            let j = i * 2;
            let x = (prev_block[0][j % 32] ^ prev_block[0][(j+1) % 32]).wrapping_add(gamma);
            let y = (ref_block[0][(x as usize) % 32] ^ prev_block[0][(x as usize + 1) % 32]).wrapping_add(prev_block[0][i]);
            result[0][i] = x ^ y;
        }
        
        result
    }

    fn compute_ref_index(&self, curr_idx: usize, prev_block: &[[u64; ARGON2_WORDS_PER_BLOCK]], lane: usize) -> usize {
        let mem_blocks = self.memory as usize;
        
        let mut rand_value = 0u64;
        for word in prev_block[0].iter() {
            rand_value = rand_value.wrapping_add(*word);
        }
        
        let segment_length = mem_blocks / (self.parallelism as usize * 4);
        let slice = (curr_idx / segment_length) % 4;
        let offset = curr_idx % segment_length;
        
        if slice == 0 || curr_idx == 0 {
            return rand_value as usize % curr_idx.max(1);
        }
        
        let start = segment_length * (slice - 1);
        let end = start + segment_length;
        
        let mut index = (rand_value as usize) % (end - start);
        if index >= offset {
            index = (index + 1) % (end - start);
        }
        
        start + index
    }

    fn get_block_index(&self, total_blocks: usize, pass: usize, slice: usize, lane: usize, segment_len: usize) -> usize {
        let slice_offset = slice * segment_len;
        let pass_offset = pass * total_blocks;
        
        let position = (pass_offset + slice_offset + lane * segment_len) % total_blocks;
        
        position
    }
}

impl Default for Argon2id {
    fn default() -> Self {
        Self::new()
    }
}

pub fn argon2id_hash(password: &[u8], salt: &[u8]) -> Vec<u8> {
    let argon2 = Argon2id::with_params(65536, 3, 4);
    argon2.derive_key(password, salt)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_argon2id_basic() {
        let password = b"test_password";
        let salt = b"unique_salt_16";
        
        let key = argon2id_hash(password, salt);
        
        assert_eq!(key.len(), 32);
        assert!(key.iter().any(|&b| b != 0));
    }
    
    #[test]
    fn test_argon2id_different_salts() {
        let password = b"test_password";
        
        let key1 = argon2id_hash(password, b"salt_number_one");
        let key2 = argon2id_hash(password, b"salt_number_two");
        
        assert_ne!(key1, key2);
    }
    
    #[test]
    fn test_argon2id_deterministic() {
        let password = b"deterministic_test";
        let salt = b"fixed_salt_value";
        
        let key1 = argon2id_hash(password, salt);
        let key2 = argon2id_hash(password, salt);
        
        assert_eq!(key1, key2);
    }
}