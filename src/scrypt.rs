use crate::{pbkdf2, CryptoErrno};

struct ScryptRom {
    b: Vec<u8>,
    r: usize,
    n: usize,
    xy: Vec<u8>,
    v: Vec<u8>,
    b32: Vec<i32>,
    x: Vec<i32>,
    xx: Vec<u8>,
}

fn blockxor(a: &[u8], b: &mut [u8]) {
    for i in 0..a.len() {
        b[i] ^= a[i];
    }
}

impl ScryptRom {
    fn romix(&mut self, i: usize, r: usize) {
        let block_start = i * 128 * r;
        let offset = (2 * r - 1) * 64;
        let block_len = 128 * r;
        self.xy[0..block_len].copy_from_slice(&self.b[block_start..(block_start + block_len)]);
        for i1 in 0..self.n {
            self.v[i1 * block_len..(i1 + 1) * block_len].copy_from_slice(&self.xy[0..block_len]);
            self.blockmix(block_len);
        }

        fn read_u32le(p: &[u8]) -> u32 {
            (p[0] as u32) + ((p[1] as u32) << 8) + ((p[2] as u32) << 16) + ((p[3] as u32) << 24)
        }

        for _ in 0..self.n {
            let j = read_u32le(&self.xy[offset..]) as usize & (self.n - 1);
            blockxor(
                &self.v[j * block_len..(j + 1) * block_len],
                &mut self.xy[0..block_len],
            );
            self.blockmix(block_len);
        }
        self.b[block_start..block_start + block_len].copy_from_slice(&self.xy[0..block_len]);
    }

    fn blockmix(&mut self, block_len: usize) {
        self.xx[0..64].copy_from_slice(&self.xy[(2 * self.r - 1) * 64..(2 * self.r) * 64]);
        for i in 0..2 * self.r {
            blockxor(&self.xy[i * 64..(i + 1) * 64], &mut self.xx[0..64]);
            self.salsa20_8();
            self.xy[block_len + (i * 64)..block_len + (i * 64) + 64]
                .copy_from_slice(&self.xx[0..64]);
        }
        for i in 0..self.r {
            self.xy.copy_within(
                block_len + (i * 2) * 64..block_len + (i * 2) * 64 + 64,
                i * 64,
            );
            self.xy.copy_within(
                block_len + (i * 2 + 1) * 64..block_len + (i * 2 + 1) * 64 + 64,
                (i + self.r) * 64,
            );
        }
    }

    fn salsa20_8(&mut self) {
        #[inline(always)]
        #[allow(non_snake_case)]
        fn R(i: i32, r: i32) -> i32 {
            i.rotate_left(r as u32)
        }

        for i in 0..16 {
            self.b32[i] = self.xx[i * 4] as i32;
            self.b32[i] |= (self.xx[i * 4 + 1] as i32) << 8;
            self.b32[i] |= (self.xx[i * 4 + 2] as i32) << 16;
            self.b32[i] |= (self.xx[i * 4 + 3] as i32) << 24;
        }

        self.x.copy_from_slice(&self.b32);

        for _ in 0..4 {
            self.x[4] ^= R(self.x[0].wrapping_add(self.x[12]), 7);
            self.x[8] ^= R(self.x[4].wrapping_add(self.x[0]), 9);
            self.x[12] ^= R(self.x[8].wrapping_add(self.x[4]), 13);
            self.x[0] ^= R(self.x[12].wrapping_add(self.x[8]), 18);
            self.x[9] ^= R(self.x[5].wrapping_add(self.x[1]), 7);
            self.x[13] ^= R(self.x[9].wrapping_add(self.x[5]), 9);
            self.x[1] ^= R(self.x[13].wrapping_add(self.x[9]), 13);
            self.x[5] ^= R(self.x[1].wrapping_add(self.x[13]), 18);
            self.x[14] ^= R(self.x[10].wrapping_add(self.x[6]), 7);
            self.x[2] ^= R(self.x[14].wrapping_add(self.x[10]), 9);
            self.x[6] ^= R(self.x[2].wrapping_add(self.x[14]), 13);
            self.x[10] ^= R(self.x[6].wrapping_add(self.x[2]), 18);
            self.x[3] ^= R(self.x[15].wrapping_add(self.x[11]), 7);
            self.x[7] ^= R(self.x[3].wrapping_add(self.x[15]), 9);
            self.x[11] ^= R(self.x[7].wrapping_add(self.x[3]), 13);
            self.x[15] ^= R(self.x[11].wrapping_add(self.x[7]), 18);
            self.x[1] ^= R(self.x[0].wrapping_add(self.x[3]), 7);
            self.x[2] ^= R(self.x[1].wrapping_add(self.x[0]), 9);
            self.x[3] ^= R(self.x[2].wrapping_add(self.x[1]), 13);
            self.x[0] ^= R(self.x[3].wrapping_add(self.x[2]), 18);
            self.x[6] ^= R(self.x[5].wrapping_add(self.x[4]), 7);
            self.x[7] ^= R(self.x[6].wrapping_add(self.x[5]), 9);
            self.x[4] ^= R(self.x[7].wrapping_add(self.x[6]), 13);
            self.x[5] ^= R(self.x[4].wrapping_add(self.x[7]), 18);
            self.x[11] ^= R(self.x[10].wrapping_add(self.x[9]), 7);
            self.x[8] ^= R(self.x[11].wrapping_add(self.x[10]), 9);
            self.x[9] ^= R(self.x[8].wrapping_add(self.x[11]), 13);
            self.x[10] ^= R(self.x[9].wrapping_add(self.x[8]), 18);
            self.x[12] ^= R(self.x[15].wrapping_add(self.x[14]), 7);
            self.x[13] ^= R(self.x[12].wrapping_add(self.x[15]), 9);
            self.x[14] ^= R(self.x[13].wrapping_add(self.x[12]), 13);
            self.x[15] ^= R(self.x[14].wrapping_add(self.x[13]), 18);
        }

        for i in 0..16 {
            self.b32[i] = self.b32[i].wrapping_add(self.x[i]);
        }

        for i in 0..16 {
            self.xx[i * 4] = (self.b32[i] & 0xff) as u8;
            self.xx[i * 4 + 1] = (self.b32[i] >> 8 & 0xff) as u8;
            self.xx[i * 4 + 2] = (self.b32[i] >> 16 & 0xff) as u8;
            self.xx[i * 4 + 3] = (self.b32[i] >> 24 & 0xff) as u8;
        }
    }
}

fn scrypt_rom(b: &[u8], r: usize, n: usize, p: usize) -> Vec<u8> {
    let mut rom = ScryptRom {
        b: b.to_vec(),
        r,
        n,
        xy: vec![0; 256 * r],
        v: vec![0; 128 * r * n],
        b32: vec![0; 16],
        x: vec![0; 16],
        xx: vec![0; 64],
    };
    for i in 0..p {
        rom.romix(i, r);
    }
    rom.b
}

/// Provides a synchronous [scrypt](https://en.wikipedia.org/wiki/Scrypt) implementation.
///
/// Scrypt is a password-based key derivation function that is designed to be expensive computationally and memory-wise in order to make brute-force attacks unrewarding.
///
/// The `salt` should be as unique as possible.
/// It is recommended that a salt is random and at least 16 bytes long.
/// See [NIST SP 800-132](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf) for details.
///
/// When passing strings for `password` or `salt`,
/// please consider [caveats when using strings as inputs to cryptographic APIs](https://nodejs.org/api/crypto.html#using-strings-as-inputs-to-cryptographic-apis).
pub fn scrypt(
    password: impl AsRef<[u8]>,
    salt: impl AsRef<[u8]>,
    n: usize,
    r: usize,
    p: usize,
    keylen: usize,
) -> Result<Vec<u8>, CryptoErrno> {
    let blen = p * 128 * r;
    let b = pbkdf2(&password, salt, 1, blen, "HMAC/SHA-256")?;
    let s = scrypt_rom(&b, r, n, p);
    let f = pbkdf2(&password, s, 1, keylen, "HMAC/SHA-256")?;
    Ok(f)
}
