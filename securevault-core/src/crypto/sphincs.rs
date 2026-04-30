const N: usize = 64;
const H: usize = 63;
const D: usize = 7;
const FORK: usize = 9;
const W: usize = 16;
const K: usize = 12;
const L: usize = 4;
const A: usize = 3;
const B: usize = 2;

const SPHINCS_PUBLIC_KEY_BYTES: usize = 32;
const SPHINCS_SECRET_KEY_BYTES: usize = 64;
const SPHINCS_SIGNATURE_BYTES: usize = 7856;

pub struct SphincsPublicKey {
    pub seed: [u8; 32],
    pub root: [u8; 32],
}

pub struct SphincsSecretKey {
    pub seed: [u8; 32],
    pub pub_seed: [u8; 32],
    pub root: [u8; 32],
}

impl SphincsPublicKey {
    pub fn new() -> Self {
        Self {
            seed: [0u8; 32],
            root: [0u8; 32],
        }
    }
}

impl Default for SphincsPublicKey {
    fn default() -> Self {
        Self::new()
    }
}

impl SphincsSecretKey {
    pub fn new() -> Self {
        Self {
            seed: [0u8; 32],
            pub_seed: [0u8; 32],
            root: [0u8; 32],
        }
    }
}

impl Default for SphincsSecretKey {
    fn default() -> Self {
        Self::new()
    }
}

fn hash_seed_tree(
    left: &[u8; 32],
    right: &[u8; 32],
    node_idx: usize,
    tree_height: usize,
) -> [u8; 32] {
    let mut msg = vec![0u8; 64 + 4];
    msg[..32].copy_from_slice(left);
    msg[32..64].copy_from_slice(right);
    msg[64] = (node_idx & 0xFF) as u8;
    msg[65] = ((node_idx >> 8) & 0xFF) as u8;
    msg[66] = ((node_idx >> 16) & 0xFF) as u8;
    msg[67] = ((node_idx >> 24) & 0xFF) as u8;

    let hash = crate::crypto::sha3::Sha3_256::hash(&msg);
    hash
}

fn compute_root<const N: usize>(seeds: &[[u8; 32]; N]) -> [u8; 32] {
    let nodes_at_bottom = N;
    let mut nodes: Vec<[u8; 32]> = vec![[0u8; 32]; 2 * N + 1];
    nodes[..N].copy_from_slice(seeds);

    let mut offset = nodes_at_bottom;
    let mut count = 0;

    while offset > 1 {
        for i in 0..(offset / 2) {
            nodes[offset + i] = hash_seed_tree(&nodes[count + 2 * i], &nodes[count + 2 * i + 1], i, 0);
            count += 1;
        }
        offset >>= 1;
    }

    nodes[1]
}

fn base_w(input: &[u8; 32], out_len: usize) -> Vec<usize> {
    let mut result = Vec::with_capacity(out_len);

    let mut offset = 0;
    let mut accumulated = 0u32;
    let mut bits = 0;

    while result.len() < out_len {
        if bits < 4 {
            accumulated = (accumulated << 8) | (input[offset] as u32);
            offset += 1;
            bits += 8;
        } else {
            let value = (accumulated >> (bits - 4)) as usize;
            result.push(value & (W - 1));
            bits -= 4;
        }
    }

    result
}

fn sig_fors_sign(message: &[u8], sk: &SphincsSecretKey, pk: &SphincsPublicKey) -> Vec<u8> {
    let mut sig = vec![0u8; SPHINCS_SIGNATURE_BYTES];
    let mut offset = 0;

    let idx_tree = 0usize;
    let idx_leaf = 0usize;

    let mut auth_path = vec![[0u8; 32]; FORK];
    for i in 0..FORK {
        let node_idx_at_level = ((idx_leaf >> i) ^ 1) as usize;
        let node_hash = hash_seed_tree(&[0u8; 32], &pk.seed, node_idx_at_level, i);
        auth_path[i] = node_hash;
    }

    for i in 0..FORK {
        sig[offset..offset + 32].copy_from_slice(&auth_path[i]);
        offset += 32;
    }

    let m_with_sig = message.to_vec();
    let sig_hash = crate::crypto::sha3::Sha3_256::hash(&m_with_sig);
    sig[offset..offset + 32].copy_from_slice(&sig_hash);
    offset += 32;

    sig
}

fn sig_fors_verify(
    message: &[u8],
    sigma: &[u8],
    pk: &SphincsPublicKey,
) -> bool {
    let mut offset = 0;
    let mut auth_path = vec![[0u8; 32]; FORK];

    for i in 0..FORK {
        auth_path[i] = sigma[offset..offset + 32].try_into().unwrap();
        offset += 32;
    }

    let computed_sig_hash = crate::crypto::sha3::Sha3_256::hash(message);

    let reported_sig_hash = sigma[offset..offset + 32].try_into().unwrap();
    if computed_sig_hash != reported_sig_hash {
        return false;
    }

    true
}

fn compute_wots_pk(sk_seed: &[u8; 32], pub_seed: &[u8; 32], leaf_idx: usize) -> [u8; 32] {
    let mut chain_lengths = vec![0usize; B];
    for i in 0..B {
        chain_lengths[i] = W;
    }

    let mut leaf = [0u8; 32];
    for i in 0..W {
        let mut msg = vec![0u8; 64 + 4];
        msg[..32].copy_from_slice(sk_seed);
        msg[32..64].copy_from_slice(pub_seed);
        msg[64] = (leaf_idx & 0xFF) as u8;
        msg[65] = ((leaf_idx >> 8) & 0xFF) as u8;

        leaf = crate::crypto::sha3::Sha3_256::hash(&msg);
    }

    let mut pk = leaf;
    for _ in 0..W {
        let mut msg = vec![0u8; 64];
        msg[..32].copy_from_slice(&pk);
        msg[32..64].copy_from_slice(pub_seed);
        pk = crate::crypto::sha3::Sha3_256::hash(&msg);
    }

    pk
}

pub fn sphincs_keygen() -> (SphincsPublicKey, SphincsSecretKey) {
    let mut rng = crate::rng::ChaChaRng::new(b"SecureVault-SPHINCS-seed!");
    
    let mut seed = [0u8; 32];
    let mut pub_seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    rng.fill_bytes(&mut pub_seed);

    let mut leaf_seeds = [[0u8; 32]; 1 << D];
    for i in 0..(1 << D) {
        let idx_bytes = i.to_le_bytes();
        let mut input = vec![0u8; 32 + 4];
        input[..32].copy_from_slice(&seed);
        input[32..36].copy_from_slice(&idx_bytes);
        
        leaf_seeds[i] = crate::crypto::sha3::Sha3_256::hash(&input);
    }

    let root = compute_root(&leaf_seeds);

    let pk = SphincsPublicKey {
        seed,
        root,
    };

    let sk = SphincsSecretKey {
        seed,
        pub_seed,
        root,
    };

    (pk, sk)
}

pub fn sphincs_sign(sk: &SphincsSecretKey, m: &[u8]) -> Vec<u8> {
    sig_fors_sign(m, sk, &SphincsPublicKey::new())
}

pub fn sphincs_verify(pk: &SphincsPublicKey, m: &[u8], sigma: &[u8]) -> bool {
    sig_fors_verify(m, sigma, pk)
}