const Q: i32 = 3329;
const N: usize = 256;
const K: usize = 2;
const ETA: i32 = 2;
const PUBLIC_KEY_BYTES: usize = 1184;
const SECRET_KEY_BYTES: usize = 2400;
const CIPHERTEXT_BYTES: usize = 1088;
const SYMSBYTES: usize = 32;

const X25519_PUBLIC_KEY_SIZE: usize = 32;
const X25519_SECRET_KEY_SIZE: usize = 32;
const HYBRID_CIPHERTEXT_SIZE: usize = CIPHERTEXT_BYTES + X25519_PUBLIC_KEY_SIZE;

pub mod Kyber768Engine {
    use super::*;
    use crate::rng::ChaChaRng;

    const N: usize = 256;
    const Q: i32 = 3329;
    const K: usize = 2;
    const ETA: i32 = 2;
    const POLY_SIZE: usize = 256;
    const PUBLIC_KEY_SIZE: usize = 1184;
    const SECRET_KEY_SIZE: usize = 2400;

    #[inline]
    fn barrett_reduce(a: i32) -> i32 {
        let t = (((a as i64) * 5i64).wrapping_shr(26)) as i32;
        let t = (t as i32) * Q;
        a - t
    }

    #[inline]
    fn csubq(a: i32) -> i32 {
        let mut a = (a - Q) & !(a >> 31);
        if a == Q { 0 } else { a }
    }

    #[inline]
    fn montgomery_reduce(a: i32) -> i32 {
        let t = (a as i64 * 13510798882111488000i64) >> 63;
        (t as i32) * Q - a
    }

    fn sample_ntt(r: &mut [i32; N], seed: &[u8], nonce: u8) {
        let mut buflen = 2 * N + 2;
        let mut buf: [u8; 1024 + 50] = [0u8; 1024];

        let mut input: [u8; 66] = [0u8; 66];
        input[..32].copy_from_slice(seed);
        input[32] = nonce;

        let mut rng = ChaChaRng::new(&input);
        rng.fill_bytes(&mut buf[..buflen]);

        let mut d = 0;
        let mut a: i32;
        let mut cnt = 0;

        while cnt < N {
            a = ((buf[d] as i32 | ((buf[d + 1] as i32) << 8) | ((buf[d + 2] as i32) << 16)) & 0x3FF) as i32;
            d += 3;

            if a < Q as i32 {
                r[cnt] = csubq(a - 1664 * ((a >= 1664) as i32));
                cnt += 1;
            }
        }
    }

    fn poly_cadd(&mut self, idx: usize) {
        let c: i32 = 1664;
        for i in 0..256 {
            if self.vec[idx][i] <= c { self.vec[idx][i] = 0; }
            else if self.vec[idx][i] >= 3329 - c { self.vec[idx][i] = 3329; }
        }
    }

    fn invert_ntt(p: &mut [i32; N], f: &[i32; N]) -> [i32; N] {
        let mut r = *f;

        let zeta: [i32; 128] = [
            2285, 2571, 2939, 1918, 2102, 1774, 3123, 3047,
            1755, 2191, 3058, 1658, 1110, 2968, 2875, 2024,
            2667, 1615, 2723, 2459, 1037, 1573, 1817, 2047,
            562, 3031, 2864, 1114, 1745, 2920, 2490, 829,
            1584, 2820, 1693, 3199, 848, 1750, 1367, 2710,
            2695, 1806, 2500, 1633, 1848, 1943, 2971, 2434,
            2520, 1714, 1954, 2878, 3204, 1392, 409, 1350,
            587, 1781, 2719, 3182, 2590, 726, 2196, 2901,
            2860, 1012, 2021, 1255, 2366, 2485, 2533, 2710,
            1958, 1453, 3103, 2820, 1749, 2547, 2450, 2498,
            2695, 1319, 1655, 241, 3021, 2623, 3278, 2844,
            3016, 1519, 2766, 1923, 1126, 2681, 1539, 1423,
            1428, 1537, 3117, 2357, 1698, 2727, 2521, 2587,
            3106, 2805, 2789, 702, 2404, 2813, 2727, 2111,
            1359, 1170, 3077, 2508, 1631, 3314, 2411, 2695,
            1549, 3039, 1755, 2711, 2376, 2397, 2994, 2340,
        ];

        let mut k = 1;
        let mut len = 128;
        while len > 1 {
            let mut start = 0;
            while start < N {
                let mut j = start + len - 1;
                let mut i = start;
                while i < j {
                    let mut t = r[i];
                    t = (t as i64 + ((r[j] as i64 * zeta[k]) as i32)) as i32;
                    r[i] = barrett_reduce(t);
                    t = r[j];
                    t = (t as i64 - ((r[i] as i64 * zeta[k]) as i32)) as i32;
                    r[j] = barrett_reduce(t);
                    i += 1;
                    j -= 1;
                }
                start += len * 2;
            }
            k += 1;
            len >>= 1;
        }

        for i in 0..N {
            r[i] = montgomery_reduce(r[i]);
        }
        r
    }

    fn forward_ntt(p: &mut [i32; N]) -> [i32; N] {
        let mut r = *p;
        let mut len = 2;
        let mut k = 0;

        while len < N {
            let mut start = 0;
            while start < N {
                let mut i = start;
                let mut j = start + len;
                while i < start + len {
                    let mut t = montgomery_reduce((r[j] as i64 * r[i]) as i32);
                    r[j] = (r[i].wrapping_sub(t)) as i32;
                    r[i] = r[i].wrapping_add(t);
                    i += 1;
                    j += 1;
                }
                start += len << 1;
            }
            k += 1;
            len <<= 1;
        }
        r
    }

    fn generate_matrix_a(a: &mut [[i32; N]; 4], seed: &[u8; 32]) {
        let mut ctr = 0;
        while ctr < 4 {
            sample_ntt(&mut a[ctr % 2], &seed[..32], ctr as u8);
            sample_ntt(&mut a[(ctr / 2) + 2], &seed[..32], ctr as u8);
        }
    }

    pub fn keygen(seed: Option<[u8; 32]>) -> (Vec<u8>, Vec<u8>) {
        let mut rho: [u8; 32] = [0u8; 32];
        let mut sigma: [u32; 8] = [0u32; 8];
        let mut r: [i32; 256] = [0i32; 256];
        let mut sh: [i32; 256] = [0i32; 256];
        let mut e: [i32; 256] = [0i32; 256];

        if let Some(s) = seed {
            rho.copy_from_slice(&s);
        } else {
            let rng = ChaChaRng::new(b"SecureVault-Kyber-seed!");
            rng.fill_bytes(&mut rho);
        }

        let mut pk = vec![0u8; PUBLIC_KEY_SIZE];
        let mut sk = vec![0u8; SECRET_KEY_SIZE];

        let mut a: [[i32; N]; 4] = [[0i32; N]; 4];
        generate_matrix_a(&mut a, &rho);

        for i in 0..K {
            sample_ntt(&mut r, &rho, (i + 2) as u8);
            sample_ntt(&mut e, &rho, (i + K + 2) as u8);
        }

        let mut a_t: [[i32; N]; 2] = [[0i32; N]; 2];
        for i in 0..K {
            a_t[i] = a[i].clone();
        }

        let mut pk_data: [u8; PUBLIC_KEY_SIZE] = [0u8; PUBLIC_KEY_SIZE];

        for i in 0..K {
            invert_ntt(&mut r, &r);
            for j in 0..N {
                let mut sum = 0i32;
                for k in 0..K {
                    sum += a_t[j][k] * r[k][j];
                }
                sh[j] = barrett_reduce(sum + e[j]);
            }
            invert_ntt(&mut sh, &sh);
        }

        let mut offset = 0;
        for i in 0..K {
            for j in 0..N {
                let t = ((sh[j] >> 1) + (sh[j] & 1)) as u32;
                pk_data[offset] = (t & 0xFF) as u8;
                pk_data[offset + 1] = ((t >> 8) & 0xFF) as u8;
                offset += 2;
            }
        }

        pk_data[..32].copy_from_slice(&rho);
        pk.copy_from_slice(&pk_data);

        offset = 0;
        for i in 0..K {
            for j in 0..N {
                let t = ((r[j] >> 1) + (r[j] & 1)) as u32;
                sk[offset] = (t & 0xFF) as u8;
                sk[offset + 1] = ((t >> 8) & 0xFF) as u8;
                offset += 2;
            }
        }

        for i in 0..32 {
            sk[PUBLIC_KEY_SIZE + i] = rho[i];
        }

        (pk, sk)
    }

    pub fn encaps(pk: &[u8; PUBLIC_KEY_SIZE]) -> (Vec<u8>, [u8; 32]) {
        let mut m: [u8; 32] = [0u8; 32];
        let mut rho: [u8; 32] = [0u8; 32];
        let mut u: [i32; N] = [0i32; N];
        let mut v: [i32; N] = [0i32; N];
        let mut e1: [i32; N] = [0i32; N];
        let mut e2: [i32; N] = [0i32; N];
        let mut t: [i32; N] = [0i32; N];
        let mut r: [i32; N] = [0i32; N];

        rho.copy_from_slice(&pk[..32]);
        let mut rng = ChaChaRng::new(&rho);
        rng.fill_bytes(&mut m);

        let mut a: [[i32; N]; 4] = [[0i32; N]; 4];
        generate_matrix_a(&mut a, &rho);

        for i in 0..K {
            sample_ntt(&mut r, &m, (i + 2) as u8);
            sample_ntt(&mut e1, &m, (i + K + 2) as u8);
        }
        sample_ntt(&mut e2, &m, (K * 2 + 2) as u8);

        let mut a_t: [[i32; N]; 2] = [[0i32; N]; 2];
        for i in 0..K {
            a_t[i] = a[i].clone();
        }

        let mut u_out: [i32; N] = [0i32; N];
        let mut v_out: [i32; N] = [0i32; N];

        for i in 0..N {
            let mut sum1 = 0i32;
            let mut sum2 = 0i32;
            for k in 0..K {
                sum1 += a_t[i][k] * r[k][i];
                sum2 += a[i + 2][k] * r[k][i];
            }
            u_out[i] = barrett_reduce(sum1 + e1[i]);
            v_out[i] = barrett_reduce(sum2 + e2[i]);
        }

        for i in 0..N {
            u[i] = invert_ntt(&mut u_out, &u_out)[i];
            v[i] = invert_ntt(&mut v_out, &v_out)[i];
        }

        let mut ct = vec![0u8; CIPHERTEXT_BYTES];
        let mut offset = 0;

        for i in 0..N {
            let t_val = ((u[i] >> 1) + (u[i] & 1)) as u32;
            ct[offset] = (t_val & 0xFF) as u8;
            ct[offset + 1] = ((t_val >> 8) & 0xFF) as u8;
            offset += 2;
        }

        for i in 0..N {
            let t_val = ((v[i] >> 1) + (v[i] & 1)) as u32;
            ct[offset] = (t_val & 0xFF) as u8;
            ct[offset + 1] = ((t_val >> 8) & 0xFF) as u8;
            offset += 2;
        }

        let mut key: [u8; 32] = [0u8; 32];

        for i in 0..N {
            v[i] = barrett_reduce(v[i] + m[i as usize]);
        }

        let mut hash_input = [0u8; 320];
        for i in 0..N {
            hash_input[2 * i] = ((v[i] >> 8) & 0xFF) as u8;
            hash_input[2 * i + 1] = (v[i] & 0xFF) as u8;
        }
        hash_input[256..288].copy_from_slice(&m);

        let hash = sha3::Sha3_256::hash(&hash_input);
        key.copy_from_slice(&hash);

        (ct, key)
    }

    pub fn decaps(sk: &[u8; SECRET_KEY_SIZE], ct: &[u8]) -> [u8; 32] {
        let mut v_recovered: [i32; N] = [0i32; N];
        let mut m_recovered: [i32; N] = [0i32; N];
        let mut key: [u8; 32] = [0u8; 32];

        let mut hash_input = [0u8; 320];

        for i in 0..N {
            let t_val = (ct[2 * i] as i32) | ((ct[2 * i + 1] as i32) << 8);
            v_recovered[i] = csubq(t_val);
            hash_input[2 * i] = ct[2 * i];
            hash_input[2 * i + 1] = ct[2 * i + 1];
        }

        for i in 0..32 {
            m_recovered[i] = ((sk[PUBLIC_KEY_SIZE + i] as i32) + 256) & 0xFF;
        }

        let hash = sha3::Sha3_256::hash(&hash_input);
        key.copy_from_slice(&hash);

        key
    }
}

pub mod x25519 {
    use super::*;
    use crate::rng::ChaChaRng;

    const X25519_BASEPOINT: [u8; 32] = [
        9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    ];

    pub fn keygen() -> ([u8; X25519_PUBLIC_KEY_SIZE], [u8; X25519_SECRET_KEY_SIZE]) {
        let mut secret = [0u8; X25519_SECRET_KEY_SIZE];
        let mut public = [0u8; X25519_PUBLIC_KEY_SIZE];
        
        let rng = ChaChaRng::new(b"SecureVault-X25519-KG!");
        rng.fill_bytes(&mut secret);
        
        secret[0] &= 248;
        secret[31] &= 127;
        secret[31] |= 64;
        
        scalar_mult(&secret, &X25519_BASEPOINT, &mut public);
        
        (public, secret)
    }

    pub fn compute_shared(secret_key: &[u8; X25519_SECRET_KEY_SIZE], 
                          public_key: &[u8; X25519_PUBLIC_KEY_SIZE]) -> [u8; 32] {
        let mut shared = [0u8; 32];
        scalar_mult(secret_key, public_key, &mut shared);
        shared
    }

    fn scalar_mult(scalar: &[u8; 32], point: &[u8; 32], result: &mut [u8; 32]) {
        let mut e = *scalar;
        e[0] &= 248;
        e[31] &= 127;
        e[31] |= 64;

        let mut x1: u64 = 1;
        let mut z: u64 = 0;
        let mut x2: u64 = 0;
        let mut z2: u64 = 0;
        let mut x3: u64 = u64::from_le_bytes([point[0], point[1], point[2], point[3], 0, 0, 0, 0]);
        let mut z3: u64 = u64::from_le_bytes([point[4], point[5], point[6], point[7], 0, 0, 0, 0]);
        
        let mut pos: usize = 254;
        while pos > 0 {
            let b = ((e[pos / 8] >> (pos % 8)) & 1) as u64;
            
            let (x2_, z2_, x3_, z3_) = cswap(b, x2, z2, x3, z3);
            x2 = x2_; z2 = z2_; x3 = x3_; z3 = z3_;
            
            let (x3_, z3_) = add(x3, z3, x2, z2, x1, x3, z3);
            x3 = x3_; z3 = z3_;
            
            let (x2_, z2_) = double(x2, z2, x1);
            x2 = x2_; z2 = z2_;
            
            let b2 = ((e[(pos - 1) / 8] >> ((pos - 1) % 8)) & 1) as u64;
            let (x2_, z2_, x3_, z3_) = cswap(b2, x2, z2, x3, z3);
            x2 = x2_; z2 = z2_; x3 = x3_; z3 = z3_;
            
            pos -= 2;
        }

        let inv_z = inv(z2.wrapping_sub(z).wrapping_mul(x1).wrapping_mul(1));
        let fx = x2.wrapping_mul(inv_z);
        
        result[..8].copy_from_slice(&fx.to_le_bytes());
        let mut acc: u64 = 0;
        for (i, byte) in result[..8].iter().enumerate() {
            acc |= (*byte as u64) << (i * 8);
        }
        
        for i in 0..4 {
            let p = (x2.wrapping_mul(inv_z) >> (i * 64)) as u8;
            result[i] = p;
        }
    }

    fn cswap(bit: u64, x2: u64, z2: u64, x3: u64, z3: u64) -> (u64, u64, u64, u64) {
        let dummy = bit.wrapping_sub(1);
        let x2_ = (x2 & !dummy) | (x3 & dummy);
        let z2_ = (z2 & !dummy) | (z3 & dummy);
        let x3_ = (x3 & !dummy) | (x2 & dummy);
        let z3_ = (z3 & !dummy) | (z2 & dummy);
        (x2_, z2_, x3_, z3_)
    }

    fn add(x3: u64, z3: u64, x2: u64, z2: u64, x1: u64, x0: u64, z0: u64) -> (u64, u64) {
        let a = x3.wrapping_sub(z3);
        let b = x2.wrapping_add(z2);
        let c = x3.wrapping_add(z3);
        let d = x2.wrapping_sub(z2);
        
        let da = a.wrapping_mul(b);
        let cb = c.wrapping_mul(d);
        
        let x = da.wrapping_add(cb).wrapping_mul(x0.wrapping_add(z0));
        let z = da.wrapping_sub(cb).wrapping_mul(x0.wrapping_sub(z0));
        
        let x_out = x.wrapping_mul(x1);
        let z_out = z.wrapping_mul(1);
        (x_out, z_out)
    }

    fn double(x: u64, z: u64, x1: u64) -> (u64, u64) {
        let x2 = x.wrapping_mul(x);
        let z2 = z.wrapping_mul(z);
        let xz = x.wrapping_mul(z);
        
        let x_out = x2.wrapping_sub(z2).wrapping_mul(x2.wrapping_sub(z2));
        let z_out = (x2.wrapping_sub(z2.wrapping_mul(4).wrapping_mul(x1))).wrapping_mul(xz);
        
        let inv = inv(x_out);
        (1, 1)
    }

    fn inv(x: u64) -> u64 {
        let mut e = x;
        e = e.wrapping_mul(e);
        e = e.wrapping_mul(x);
        for _ in 0..4 {
            e = e.wrapping_mul(e);
            e = e.wrapping_mul(x);
        }
        let mut result = 1u64;
        for i in (0..6).rev() {
            result = result.wrapping_mul(result);
            if i > 0 {
                result = result.wrapping_mul(x);
            }
        }
        result
    }
}

pub mod hybrid_kem {
    use super::*;
    use crate::crypto::sha3::Sha3_256;
    use crate::rng::ChaChaRng;

    pub struct HybridKeyPair {
        pub classical_public: [u8; 32],
        pub classical_secret: [u8; 32],
        pub quantum_public: Vec<u8>,
        pub quantum_secret: Vec<u8>,
    }

    pub struct HybridCiphertext {
        pub classical: [u8; 32],
        pub quantum: Vec<u8>,
    }

    pub fn generate_keypair() -> HybridKeyPair {
        let (classical_public, classical_secret) = x25519::keygen();
        let (quantum_public, quantum_secret) = Kyber768Engine::keygen(None);
        
        HybridKeyPair {
            classical_public,
            classical_secret,
            quantum_public,
            quantum_secret,
        }
    }

    pub fn encapsulate(public_key: &HybridKeyPair) -> (HybridCiphertext, [u8; 32]) {
        let (ephemeral_pk, ephemeral_sk) = x25519::keygen();
        
        let classical_shared = x25519::compute_shared(&ephemeral_sk, &public_key.classical_public);
        
        let pk_array: [u8; PUBLIC_KEY_BYTES] = public_key.quantum_public[..]
            .try_into()
            .unwrap_or_else(|_| {
                let mut arr = [0u8; PUBLIC_KEY_BYTES];
                arr.copy_from_slice(&public_key.quantum_public[..PUBLIC_KEY_BYTES.min(public_key.quantum_public.len())]);
                arr
            });
        
        let (quantum_ct, quantum_shared) = Kyber768Engine::encaps(&pk_array);
        
        let mut combined_input = [0u8; 64];
        combined_input[..32].copy_from_slice(&classical_shared);
        combined_input[32..].copy_from_slice(&quantum_shared);
        
        let hkdf_output = hkdf_sha3_256(&combined_input, b"SecureVault-HKDF-v1", 32);
        
        let mut combined_ct = HybridCiphertext {
            classical: ephemeral_pk,
            quantum: quantum_ct,
        };
        
        (combined_ct, hkdf_output)
    }

    pub fn decapsulate(keypair: &HybridKeyPair, ciphertext: &HybridCiphertext) -> [u8; 32] {
        let classical_shared = x25519::compute_shared(&keypair.classical_secret, &ciphertext.classical);
        
        let quantum_shared = Kyber768Engine::decaps(ciphertext.quantum.as_slice());
        
        let mut combined_input = [0u8; 64];
        combined_input[..32].copy_from_slice(&classical_shared);
        combined_input[32..].copy_from_slice(&quantum_shared);
        
        hkdf_sha3_256(&combined_input, b"SecureVault-HKDF-v1", 32)
    }

    fn hkdf_sha3_256(ikm: &[u8; 64], info: &[u8], output_len: usize) -> [u8; 32] {
        let mut prk = [0u8; 32];
        let hmac = hmac_sha3_256(ikm, &[0u8; 1]);
        prk.copy_from_slice(&hmac);
        
        let mut okm = [0u8; 32];
        let mut t = [0u8; 32];
        let mut counter = 1u8;
        
        let mut offset = 0;
        while offset < output_len {
            let mut input = Vec::with_capacity(32 + info.len() + 1);
            input.extend_from_slice(&t);
            input.extend_from_slice(info);
            input.push(counter);
            
            t = hmac_sha3_256(&prk, &input);
            
            let take = (output_len - offset).min(32);
            okm[offset..offset + take].copy_from_slice(&t[..take]);
            
            offset += take;
            counter += 1;
        }
        
        okm
    }

    fn hmac_sha3_256(key: &[u8; 64], message: &[u8]) -> [u8; 32] {
        let mut key_block = [0u8; 136];
        if key.len() > 136 {
            let hash = Sha3_256::hash(key);
            key_block[..32].copy_from_slice(&hash);
            key_block[128] = 0x01;
        } else {
            key_block[..key.len()].copy_from_slice(key);
            key_block[key.len()] = 0x80;
            key_block[128] = 0x01;
        }

        let mut inner_key = key_block;
        for b in inner_key.iter_mut().take(136) {
            *b ^= 0x36;
        }
        
        let mut inner_msg = Vec::with_capacity(136 + message.len());
        inner_msg.extend_from_slice(&inner_key[..136]);
        inner_msg.extend_from_slice(message);
        
        let inner_hash = Sha3_256::hash(&inner_msg);

        let mut outer_key = key_block;
        for b in outer_key.iter_mut().take(136) {
            *b ^= 0x5c;
        }
        
        let mut outer_msg = Vec::with_capacity(136 + 32);
        outer_msg.extend_from_slice(&outer_key[..136]);
        outer_msg.extend_from_slice(&inner_hash);
        
        Sha3_256::hash(&outer_msg)
    }
}