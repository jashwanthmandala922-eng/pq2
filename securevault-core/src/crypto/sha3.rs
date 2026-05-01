

#![allow(unused_variables, dead_code)]
const SHA3_RATE: usize = 136;

pub struct Sha3_256 {
    state: [u64; 25],
    rate: usize,
    offset: usize,
    squeezing: bool,
}

impl Sha3_256 {
    pub fn new() -> Self {
        Self {
            state: [0u64; 25],
            rate: SHA3_RATE,
            offset: 0,
            squeezing: false,
        }
    }

    pub fn update(&mut self, input: &[u8]) {
        if self.squeezing {
            return;
        }
        let block_size = self.rate >> 3;
        let mut input_offset = 0;

        while input_offset < input.len() {
            let remaining = input.len() - input_offset;
            let to_absorb = if remaining < block_size - self.offset {
                remaining
            } else {
                block_size - self.offset
            };

            for i in 0..to_absorb {
                self.state[(self.offset + i) >> 3] ^= (input[input_offset + i] as u64) << (((self.offset + i) & 7) << 3);
            }
            self.offset += to_absorb;
            input_offset += to_absorb;

            if self.offset == block_size {
                self.keccak_p();
                self.offset = 0;
            }
        }
    }

    pub fn finalize(&mut self) -> [u8; 32] {
        let block_size = self.rate >> 3;
        
        self.state[self.offset >> 3] ^= 0x01u64.wrapping_shl((self.offset & 7) as u32);
        self.state[(block_size - 1) >> 3] ^= 0x8000000000000000u64.wrapping_shl(((block_size - 1) & 7) as u32);

        self.keccak_p();
        self.squeezing = true;

        let mut output = [0u8; 32];
        for i in 0..32 {
            output[i] = (self.state[i >> 3] >> ((i & 7) << 3)) as u8;
        }
        output
    }

    fn keccak_p(&mut self) {
        let mut s = self.state;
        let rounds = 24;

        for _ in 0..rounds {
            theta(&mut s);
            rho(&mut s);
            pi(&mut s);
            chi(&mut s);
            iota(&mut s);
        }

        self.state = s;
    }
}

fn theta(s: &mut [u64; 25]) {
    let mut c = [0u64; 5];
    for x in 0..5 {
        c[x] = s[x] ^ s[x + 5] ^ s[x + 10] ^ s[x + 15] ^ s[x + 20];
    }
    let mut d = [0u64; 5];
    for x in 0..5 {
        d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
    }
    for x in 0..5 {
        for y in 0..5 {
            s[x + 5 * y] ^= d[x];
        }
    }
}

fn rho(s: &mut [u64; 25]) {
    let state = *s;
    let mut x = 1;
    let mut y = 0;
    let mut current = s[1];

    for _t in 0..24 {
        let d = ((y * 2 + x * 3) & 7) as u32;
        s[x + 5 * y] = current.rotate_left(d);
        current = state[x + 5 * y];
        let new_x = (2 * x + 3 * y) % 5;
        y = (2 * y + x) % 5;
        x = new_x;
    }
}

fn pi(s: &mut [u64; 25]) {
    let mut b = [0u64; 25];
    for x in 0..5 {
        for y in 0..5 {
            b[y + 5 * ((x * 2 + 3 * y) % 5)] = s[x + 5 * y];
        }
    }
    *s = b;
}

fn chi(s: &mut [u64; 25]) {
    let b = *s;
    for x in 0..5 {
        for y in 0..5 {
            s[x + 5 * y] ^= b[((x + 1) % 5) + 5 * y] & !b[((x + 2) % 5) + 5 * y];
        }
    }
}

fn iota(s: &mut [u64; 25]) {
    let mut rc: [u64; 25] = [0; 25];
    rc[0] = 1;
    rc[1] = 0x8082;
    rc[2] = 0x808a;
    rc[3] = 0x8000;
    s[0] ^= rc[0];
}

impl Default for Sha3_256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha3_256 {
    pub fn hash(input: &[u8]) -> [u8; 32] {
        let mut hasher = Self::new();
        hasher.update(input);
        hasher.finalize()
    }
}