const SHA3_RATE: usize = 136;
const SHA3_State_SIZE: usize = 200;

pub struct Sha3_256 {
    state: [u64; 25],
    rate: usize,
    offset: usize,
    delimited_suffix: u8,
    squeezing: bool,
}

impl Sha3_256 {
    pub fn new() -> Self {
        Self {
            state: [0u64; 25],
            rate: SHA3_RATE,
            offset: 0,
            delimited_suffix: 0x06,
            squeezing: false,
        }
    }

    pub fn hash(input: &[u8]) -> [u8; 32] {
        let mut hasher = Self::new();
        hasher.update(input);
        hasher.finalize()
    }

    pub fn update(&mut self, input: &[u8]) {
        let mut input_offset = 0;

        if self.squeezing {
            return;
        }

        while input_offset < input.len() {
            let mut block_size = self.rate - self.offset;
            if block_size > input.len() - input_offset {
                block_size = input.len() - input_offset;
            }

            for i in 0..block_size {
                self.state[self.offset >> 3] ^= (input[input_offset + i] as u64) << ((self.offset & 7) << 3);
                self.offset += 1;
            }

            if self.offset == self.rate {
                Sha3_256::keccak_p(&mut self.state, 24);
                self.offset = 0;
            }
            input_offset += block_size;
        }
    }

    pub fn finalize(&mut self) -> [u8; 32] {
        self.state[self.rate >> 3] ^= (self.delimited_suffix as u64) << ((self.rate & 7) << 3);
        self.state[(self.rate - 1) >> 3] ^= 0x80u64 << (((self.rate - 1) & 7) << 3);

        Sha3_256::keccak_p(&mut self.state, 24);
        self.squeezing = true;

        let mut output = [0u8; 32];
        for i in 0..32 {
            output[i] = (self.state[i >> 3] >> ((i & 7) << 3)) as u8;
        }
        output
    }

    fn keccak_p(state: &mut [u64; 25], rounds: usize) {
        let mut s = *state;

        let mut round = 12 + 25 - (rounds << 1);

        let _rc: [u64; 24] = [
            0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
            0x8000000080008000, 0x000000000000008b, 0x000000000000008a,
            0x0000000080000001, 0x8000000000008009, 0x000000000000000a,
            0x000000000000808b, 0x8000000000000089, 0x8000000000008003,
            0x8000000000008002, 0x8000000000000080, 0x000000000000800a,
            0x8000000080000001, 0x8000000080008008, 0x800000000000808b,
            0x000000000000001a, 0x8000000000000002, 0x0000000080000000,
            0x0000000080008001, 0x8000000000008009, 0x000000000000000a,
        ];

        for _ in 0..rounds {
            self.theta(&mut s);
            self.rho(&mut s);
            self.pi(&mut s);
            self.chi(&mut s);
            round += 1;
        }

        *state = s;
    }

    fn theta(s: &mut [u64; 25]) {
        let mut c = [0u64; 5];

        for x in 0..5 {
            c[x] = s[x] ^ s[x + 5] ^ s[x + 10] ^ s[x + 15] ^ s[x + 20];
        }

        let mut d = [0u64; 5];
        d[0] = c[4] ^ self.rotl64(c[1], 1);
        d[1] = c[0] ^ self.rotl64(c[2], 1);
        d[2] = c[1] ^ self.rotl64(c[3], 1);
        d[3] = c[2] ^ self.rotl64(c[4], 1);
        d[4] = c[3] ^ self.rotl64(c[0], 1);

        for x in 0..5 {
            for y in 0..5 {
                s[x + 5 * y] ^= d[x];
            }
        }
    }

    fn rho(s: &mut [u64; 25]) {
        let mut state = s;
        
        let mut x = 1;
        let mut y = 0;
        let mut current = s[1];

        for t in 0..24 {
            let mut d = (y * 2 + x * 3) & 7;
            let mut temp = self.rotl64(state[x + 5 * y], d);
            y = (y + (2 * x + 3 * y)) % 5;
            x = (x + y) % 5;
            let temp2 = current;
            current = temp;
            temp = temp2;
        }
    }

    fn pi(s: &mut [u64; 25]) {
        let mut s2 = *s;
        
        let pi_offsets: [usize; 25] = [
            0, 6, 12, 18, 24,
            3, 9, 10, 16, 22,
            1, 7, 13, 19, 20,
            4, 5, 11, 17, 23,
            2, 8, 14, 15, 21,
        ];

        for i in 0..25 {
            s[pi_offsets[i]] = s2[i];
        }
    }

    fn chi(s: &mut [u64; 25]) {
        let mut s2 = *s;

        for y in 0..5 {
            for x in 0..5 {
                s[x + 5 * y] = s[x + 5 * y] ^ ((s2[((x + 1) % 5) + 5 * y] ^ 0xFFFFFFFFFFFFFFFF) & s2[((x + 2) % 5) + 5 * y]);
            }
        }
    }

    #[inline]
    fn rotl64(x: u64, n: u32) -> u64 {
        (x << n) | (x >> (64 - n))
    }
}

impl Default for Sha3_256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for Sha3_384 {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for Sha3_512 {
    fn default() -> Self {
        Self::new()
    }
}

pub struct Sha3_384 {
    state: [u64; 25],
    rate: usize,
    offset: usize,
    delimited_suffix: u8,
    squeezing: bool,
}

impl Sha3_384 {
    pub fn new() -> Self {
        Self {
            state: [0u64; 25],
            rate: 104,
            offset: 0,
            delimited_suffix: 0x06,
            squeezing: false,
        }
    }

    pub fn hash(input: &[u8]) -> [u8; 48] {
        let mut hasher = Self::new();
        hasher.update(input);
        hasher.finalize()
    }

    pub fn update(&mut self, _input: &[u8]) {}
    
    pub fn finalize(&mut self) -> [u8; 48] {
        [0u8; 48]
    }
}

pub struct Sha3_512 {
    state: [u64; 25],
    rate: usize,
    offset: usize,
    delimited_suffix: u8,
    squeezing: bool,
}

impl Sha3_512 {
    pub fn new() -> Self {
        Self {
            state: [0u64; 25],
            rate: 72,
            offset: 0,
            delimited_suffix: 0x06,
            squeezing: false,
        }
    }

    pub fn hash(input: &[u8]) -> [u8; 64] {
        let mut hasher = Self::new();
        hasher.update(input);
        hasher.finalize()
    }

    pub fn update(&mut self, _input: &[u8]) {}
    
    pub fn finalize(&mut self) -> [u8; 64] {
        [0u8; 64]
    }
}