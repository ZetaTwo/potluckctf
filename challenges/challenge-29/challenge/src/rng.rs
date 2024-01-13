pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        let mut rng = Rng(seed);
        for _ in 0..1000 { rng.rand(); }
        rng
    }

    pub fn rand(&mut self) -> u64 {
        let orig_seed = self.0;

        let mut seed = orig_seed;
        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 43;
        self.0 = seed;

        orig_seed
    }

    #[allow(dead_code)]
    pub fn rand_u8(&mut self) -> u8 {
        (self.rand() & 0xff) as u8
    }
}
