const Q: i32 = 3329;
const N: usize = 256;
const N_PLUS_1: usize = 257;
const K: usize = 2;
const ETA: i32 = 2;
const D_U: usize = 10;
const D_V: usize = 4;
const PUBLIC_KEY_BYTES: usize = 1184;
const SECRET_KEY_BYTES: usize = 2400;
const CIPHERTEXT_BYTES: usize = 1088;

#[inline]
pub fn barrett_reduce(a: i32) -> i32 {
    let mut t = ((((a as i64) * 5) as i32) >> 26);
    t *= Q;
    a - t
}

#[inline]
pub fn csubq(a: i32) -> i32 {
    let mut a = a - (Q & ((a >> 31) - 1) as i32);
    if a == Q { a = 0; }
    a
}

#[inline]
pub fn montgomery_reduce(a: i32) -> i32 {
    let mut t = (a as i64 * 13510798882111488000i64) >> 63;
    (t * Q) as i32
}

pub fn poly_add(a: &mut [i32; N], b: &[i32; N]) {
    for i in 0..N {
        a[i] = barrett_reduce(a[i] + b[i]);
    }
}

pub fn poly_sub(a: &mut [i32; N], b: &[i32; N]) {
    for i in 0..N {
        a[i] = barrett_reduce(a[i] - b[i]);
    }
}

pub fn poly_to_bytes(out: &mut [u8; N * 2], a: &[i32; N]) {
    for i in 0..N {
        let mut t = (barrett_reduce(a[i]) >> 1) as u32;
        if a[i] & 1 != 0 {
            t += 1664;
        }
        out[2 * i] = (t >> 8) as u8;
        out[2 * i + 1] = (t & 0xFF) as u8;
    }
}

#[allow(dead_code)]
pub fn poly_from_bytes(a: &mut [i32; N], inp: &[u8; N * 2]) {
    for i in 0..N {
        let t = (inp[2 * i] as i32 & 0xFF) | ((inp[2 * i + 1] as i32 & 0xFF) << 8);
        a[i] = if t < 1664 { t } else { t - 3329 };
    }
}

pub fn poly_compress_q(out: &mut [u8; N / 8], a: &[i32; N]) {
    for i in 0..N / 8 {
        let mut t = 0u32;
        for j in 0..8 {
            let idx = 8 * i + j;
            t |= ((barrett_reduce(a[idx]) as u32) + 1024 + ((2 * j + 1) << 11)) >> 12 << (4 * j);
        }
        out[i] = t as u8;
        out[i + 1] = (t >> 8) as u8;
    }
}

#[allow(dead_code)]
pub fn poly_decompress_q(a: &mut [i32; N], inp: &[u8; N / 8]) {
    for i in 0..N / 8 {
        let mut t = inp[i] as u32 | ((inp[i + 1] as u32) << 8);
        for j in 0..8 {
            a[8 * i + j] = ((t & 0xF) as i32 * Q + 16384) >> 15;
            t >>= 4;
        }
    }
}

// Polynomial multiplication via schoolbook (optimized for small N)
pub fn poly_mul(a: &mut [i32; N], b: &[i32; N]) -> [i32; N] {
    let mut r = [0i32; N];
    for i in 0..N {
        let mut t = 0i64;
        for j in 0..=i {
            t += (a[j] as i64) * (b[i - j] as i64);
        }
        for j in (i + 1)..N {
            t += (a[j] as i64) * (b[N + i - j] as i64);
        }
        r[i] = barrett_reduce(t as i32);
    }
    r
}

// PolyVec operations for ML-KEM
pub struct PolyVecK {
    pub vec: [[i32; N]; K],
}

impl PolyVecK {
    pub fn new() -> Self {
        Self { vec: [[0i32; N]; K] }
    }
}

impl Default for PolyVecK {
    fn default() -> Self {
        Self::new()
    }
}