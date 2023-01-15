//! `crypto-wasi` is subset of apis of nodejs's crypto module for wasm32-wasi,
//! implemented in rust,
//! powered by [WASI Cryptography APIs](https://github.com/WebAssembly/wasi-crypto).
//! This library is developed and tested over [WasmEdge](https://github.com/WasmEdge/WasmEdge) runtime
//!
//! **Note:** The api of this library is **not completely consistent** with the api of nodejs.
//!
//! # Currently Subset Implemented
//!
//! - `createHash` (sha256, sha512, sha512-256)
//! - `createHmac` (sha256, sha512)
//! - `hkdf` (sha256, sha512)
//! - `pbkdf2` (sha256, sha512)
//! - `scrypt`
//! - `createCipheriv` & `createDecipheriv` (aes-128-gcm, aes-256-gcm, chacha20-poly1305)
//!
//! # Not Implemented
//! - `createCipher` & `createDecipher`:
//! This function is semantically insecure for all supported ciphers and fatally flawed for ciphers in counter mode (such as CTR, GCM, or CCM).
//! - `createSecretKey`:
//! In nodejs, `SecretKey` is just store the raw key data.
//! In wasi-crypto, `SymmetricKey` is equivalent to `SecretKey`,
//! which is also just store the raw key data in WasmEdge's implementation.
//! But in wasi-crypto, each key is required to be bound to a kind of algorithms,
//! which cause some complications when managing keys and reusing keys.
//! So we're not going to implement `SecretKey`.

/// Low-level binding to `wasi-crypto`
pub mod raw;

/// Some helpful tools and simpified api
pub mod utils;

pub type CryptoErrno = raw::CryptoErrno;

const NONE_OPTS: raw::OptOptions = raw::OptOptions {
    tag: raw::OPT_OPTIONS_U_NONE.raw(),
    u: raw::OptOptionsUnion { none: () },
};

const NONE_KEY: raw::OptSymmetricKey = raw::OptSymmetricKey {
    tag: raw::OPT_SYMMETRIC_KEY_U_NONE.raw(),
    u: raw::OptSymmetricKeyUnion { none: () },
};

/// Equivalent to `crypto.Hmac`
///
/// Example:
///
/// ```
/// use crate::Hmac;
///
/// let mut h = Hmac::create("sha256", "key")?;
/// h.update("abc")?;
/// h.update("def")?;
/// let res = h.digest()?;
/// ```
pub struct Hmac {
    handle: raw::SymmetricState,
}

impl Hmac {
    /// Equivalent to `createHmac`
    ///
    /// In nodejs, the `key` argument can pass a `KeyObject`.
    /// While in nodejs, `SecretKey` is just store the raw key data.
    /// In wasi-crypto, `SymmetricKey` is equivalent to `SecretKey`,
    /// which is also just store the raw key data in WasmEdge's implementation.
    /// But in wasi-crypto, each key is required to be bound to a kind of algorithms,
    /// which cause some complications when managing keys and reusing keys.
    /// So we're not going to implement `SecretKey`.
    pub fn create<T>(alg: &str, key: T) -> Result<Self, CryptoErrno>
    where
        T: AsRef<[u8]>,
    {
        let alg = match alg {
            "sha256" | "SHA256" | "HMAC/SHA-256" => "HMAC/SHA-256",
            "sha512" | "SHA512" | "HMAC/SHA-512" => "HMAC/SHA-512",
            _ => return Err(raw::CRYPTO_ERRNO_UNSUPPORTED_ALGORITHM),
        };
        let handle = {
            let key = key.as_ref();
            unsafe {
                let key = raw::symmetric_key_import(alg, key.as_ptr(), key.len())?;
                let opt = raw::OptSymmetricKey {
                    tag: raw::OPT_SYMMETRIC_KEY_U_SOME.raw(),
                    u: raw::OptSymmetricKeyUnion { some: key },
                };
                let state = raw::symmetric_state_open(alg, opt, NONE_OPTS)?;
                raw::symmetric_key_close(key)?;
                state
            }
        };
        Ok(Self { handle })
    }

    /// Updates the `Hmac` content with the given `data`.
    /// This can be called many times with new data as it is streamed.
    pub fn update(&mut self, data: impl AsRef<[u8]>) -> Result<(), CryptoErrno> {
        let data = data.as_ref();
        unsafe { raw::symmetric_state_absorb(self.handle, data.as_ptr(), data.len()) }
    }

    /// Calculates the HMAC digest of all of the data passed using `update`.
    /// The `Hmac` object SHOULD NOT be used again after `digest` has been called.
    /// Unlike nodejs, you can still call `update` to append content and `digest` to compute for all content actually in WasmEdge's implementation,
    /// but it's NOT RECOMMENDED.
    pub fn digest(&mut self) -> Result<Vec<u8>, CryptoErrno> {
        unsafe {
            let tag = raw::symmetric_state_squeeze_tag(self.handle)?;
            let len = raw::symmetric_tag_len(tag)?;
            let mut out = vec![0; len];
            raw::symmetric_tag_pull(tag, out.as_mut_ptr(), out.len())?;
            raw::symmetric_tag_close(tag)?;
            Ok(out)
        }
    }

    /// As same as `digest` but directly write result to `buf`
    pub fn digest_into(&mut self, mut buf: impl AsMut<[u8]>) -> Result<(), CryptoErrno> {
        let buf = buf.as_mut();
        unsafe {
            let tag = raw::symmetric_state_squeeze_tag(self.handle)?;
            raw::symmetric_tag_pull(tag, buf.as_mut_ptr(), buf.len())?;
            raw::symmetric_tag_close(tag)?;
        }
        Ok(())
    }
}

impl Drop for Hmac {
    fn drop(&mut self) {
        unsafe {
            raw::symmetric_state_close(self.handle).unwrap();
        }
    }
}

/// Creates and returns an `Hmac` object that uses the given algorithm and key.
pub fn create_hmac(alg: &str, key: impl AsRef<[u8]>) -> Result<Hmac, CryptoErrno> {
    Hmac::create(alg, key)
}

/// Equivalent to `crypto.Hash`
///
/// Example:
///
/// ```
/// use crate::Hash;
///
/// let mut h = Hash::create("sha256")?;
/// h.update("abc")?;
/// h.update("def")?;
/// let res = h.digest()?;
/// ```
pub struct Hash {
    handle: raw::SymmetricState,
    hash_len: usize,
}

impl Hash {
    /// Equivalent to `createHash`
    pub fn create(alg: &str) -> Result<Self, CryptoErrno> {
        let (alg, hash_len) = match alg {
            "sha256" | "SHA256" | "SHA-256" => ("SHA-256", 32),
            "sha512" | "SHA512" | "SHA-512" => ("SHA-512", 64),
            "sha512-256" | "SHA512-256" | "SHA-512/256" => ("SHA-512/256", 32),
            _ => return Err(raw::CRYPTO_ERRNO_UNSUPPORTED_ALGORITHM),
        };
        let handle = { unsafe { raw::symmetric_state_open(alg, NONE_KEY, NONE_OPTS)? } };
        Ok(Self { handle, hash_len })
    }

    /// Updates the `Hash` content with the given `data`.
    /// This can be called many times with new data as it is streamed.
    pub fn update(&mut self, data: impl AsRef<[u8]>) -> Result<(), CryptoErrno> {
        let data = data.as_ref();
        unsafe { raw::symmetric_state_absorb(self.handle, data.as_ptr(), data.len()) }
    }

    /// Creates a new `Hash` object that contains a deep copy of the internal state of the current `Hash` object.
    pub fn copy(&self) -> Result<Self, CryptoErrno> {
        let new_handle = unsafe { raw::symmetric_state_clone(self.handle) }?;
        Ok(Self {
            handle: new_handle,
            hash_len: self.hash_len,
        })
    }

    /// Calculates the HASH digest of all of the data passed using `update`.
    /// The `Hash` object SHOULD NOT be used again after `digest` has been called.
    /// Unlike nodejs, you can still call `update` to append content and `digest` to compute for all content actually in WasmEdge's implementation,
    /// but it's NOT RECOMMENDED.
    pub fn digest(&mut self) -> Result<Vec<u8>, CryptoErrno> {
        let mut out = vec![0; self.hash_len];
        self.digest_into(&mut out)?;
        Ok(out)
    }

    /// As same as `digest` but directly write result to `buf`
    pub fn digest_into(&mut self, mut buf: impl AsMut<[u8]>) -> Result<(), CryptoErrno> {
        let buf = buf.as_mut();
        unsafe {
            raw::symmetric_state_squeeze(self.handle, buf.as_mut_ptr(), buf.len())?;
        }
        Ok(())
    }
}

impl Drop for Hash {
    fn drop(&mut self) {
        unsafe {
            raw::symmetric_state_close(self.handle).unwrap();
        }
    }
}

impl Clone for Hash {
    fn clone(&self) -> Self {
        self.copy().unwrap()
    }
}

/// Creates and returns a `Hash` object that can be used to generate hash digests using the given algorithm.
pub fn create_hash(alg: &str) -> Result<Hash, CryptoErrno> {
    Hash::create(alg)
}

fn hkdf_extract(
    alg: &str,
    key: impl AsRef<[u8]>,
    salt: impl AsRef<[u8]>,
) -> Result<raw::SymmetricKey, CryptoErrno> {
    let (extract_alg, expand_alg) = match alg {
        "sha256" | "SHA256" => ("HKDF-EXTRACT/SHA-256", "HKDF-EXPAND/SHA-256"),
        "sha512" | "SHA512" => ("HKDF-EXTRACT/SHA-512", "HKDF-EXPAND/SHA-512"),
        _ => return Err(raw::CRYPTO_ERRNO_UNSUPPORTED_ALGORITHM),
    };
    let key = key.as_ref();
    let salt = salt.as_ref();
    if !key.is_empty() {
        unsafe {
            let extract_key = raw::symmetric_key_import(extract_alg, key.as_ptr(), key.len())?;
            let extract_handle = raw::symmetric_state_open(
                extract_alg,
                raw::OptSymmetricKey {
                    tag: raw::OPT_SYMMETRIC_KEY_U_SOME.raw(),
                    u: raw::OptSymmetricKeyUnion { some: extract_key },
                },
                NONE_OPTS,
            )?;
            raw::symmetric_state_absorb(extract_handle, salt.as_ptr(), salt.len())?;
            let expand_key = raw::symmetric_state_squeeze_key(extract_handle, expand_alg)?;
            raw::symmetric_state_close(extract_handle)?;
            raw::symmetric_key_close(extract_key)?;
            Ok(expand_key)
        }
    } else {
        let res = utils::hmac(alg, salt, &[key])?;
        unsafe { raw::symmetric_key_import(expand_alg, res.as_ptr(), res.len()) }
    }
}

fn hkdf_extract_raw(
    alg: &str,
    key: impl AsRef<[u8]>,
    salt: impl AsRef<[u8]>,
) -> Result<Vec<u8>, CryptoErrno> {
    utils::hmac(alg, salt, &[key])
}

/// As same as `hkdf`, but use hmac to manual expand
///
/// See [https://github.com/WasmEdge/WasmEdge/issues/2176](https://github.com/WasmEdge/WasmEdge/issues/2176)
pub fn hkdf_hmac(
    alg: &str,
    key: impl AsRef<[u8]>,
    salt: impl AsRef<[u8]>,
    info: impl AsRef<[u8]>,
    key_len: usize,
) -> Result<Vec<u8>, CryptoErrno> {
    let key = key.as_ref();
    let salt = salt.as_ref();
    let info = info.as_ref();
    let (_, _, hash_len) = match alg {
        "sha256" | "SHA256" => ("HKDF-EXTRACT/SHA-256", "HKDF-EXPAND/SHA-256", 32),
        "sha512" | "SHA512" => ("HKDF-EXTRACT/SHA-512", "HKDF-EXPAND/SHA-512", 64),
        _ => return Err(raw::CRYPTO_ERRNO_UNSUPPORTED_ALGORITHM),
    };
    let expand_key = hkdf_extract_raw(alg, key, salt)?;
    let mut out = vec![0; key_len];
    let mut last = [].as_slice();
    for (idx, chunk) in out.chunks_mut(hash_len).enumerate() {
        let counter = [idx as u8 + 1];
        chunk.clone_from_slice(
            &utils::hmac(alg, &expand_key, &[last, info, &counter])?[..chunk.len()],
        );
        last = chunk;
    }
    Ok(out)
}

/// HKDF is a simple key derivation function defined in RFC 5869.
///
/// If you don't set `key_len` to 32 for `sha256` or 64 for `sha512` and get `WASI_CRYPTO_ERRNO_ALGORITHM_FAILURE` error,
/// please use `hkdf_hmac` instead.  
pub fn hkdf(
    alg: &str,
    ikm: impl AsRef<[u8]>,
    salt: impl AsRef<[u8]>,
    info: impl AsRef<[u8]>,
    key_len: usize,
) -> Result<Vec<u8>, CryptoErrno> {
    let key = ikm.as_ref();
    let salt = salt.as_ref();
    let info = info.as_ref();
    let (_, expand_alg) = match alg {
        "sha256" | "SHA256" => ("HKDF-EXTRACT/SHA-256", "HKDF-EXPAND/SHA-256"),
        "sha512" | "SHA512" => ("HKDF-EXTRACT/SHA-512", "HKDF-EXPAND/SHA-512"),
        _ => return Err(raw::CRYPTO_ERRNO_UNSUPPORTED_ALGORITHM),
    };
    let mut out = vec![0; key_len];
    let expand_key = hkdf_extract(alg, key, salt)?;
    unsafe {
        let expand_handle = raw::symmetric_state_open(
            expand_alg,
            raw::OptSymmetricKey {
                tag: raw::OPT_SYMMETRIC_KEY_U_SOME.raw(),
                u: raw::OptSymmetricKeyUnion { some: expand_key },
            },
            NONE_OPTS,
        )?;
        raw::symmetric_state_absorb(expand_handle, info.as_ptr(), info.len())?;
        raw::symmetric_state_squeeze(expand_handle, out.as_mut_ptr(), out.len())?;
        raw::symmetric_state_close(expand_handle)?;
        raw::symmetric_key_close(expand_key)?;
    }
    Ok(out)
}

/// Password-Based Key Derivation Function 2 (PBKDF2) implementation.
///
/// A selected HMAC digest algorithm specified by `digest` is applied to derive a key of the requested byte length (`key_len`) from the `password`, `salt` and `iterations`.
/// The `iterations` argument must be a number set as high as possible.
/// The higher the number of iterations,
/// the more secure the derived key will be,
/// but will take a longer amount of time to complete.
///
/// The `salt` should be as unique as possible.
/// It is recommended that a salt is random and at least 16 bytes long.
/// See [NIST SP 800-132](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf) for details.
///
/// When passing strings for `password` or `salt`,
/// please consider [caveats when using strings as inputs to cryptographic APIs](https://nodejs.org/api/crypto.html#using-strings-as-inputs-to-cryptographic-apis).
pub fn pbkdf2(
    password: impl AsRef<[u8]>,
    salt: impl AsRef<[u8]>,
    iterations: usize,
    key_len: usize,
    digest: &str,
) -> Result<Vec<u8>, CryptoErrno> {
    let hash_len = match digest {
        "sha256" | "SHA256" | "HMAC/SHA-256" => 32,
        "sha512" | "SHA512" | "HMAC/SHA-512" => 64,
        _ => return Err(raw::CRYPTO_ERRNO_UNSUPPORTED_ALGORITHM),
    };
    let mut out = vec![0; key_len];
    for (idx, chunk) in out.chunks_mut(hash_len).enumerate() {
        let mut salt_2 = salt.as_ref().to_vec();
        let idx = idx + 1;
        salt_2.push(((idx >> 24) & 0xff) as u8);
        salt_2.push(((idx >> 16) & 0xff) as u8);
        salt_2.push(((idx >> 8) & 0xff) as u8);
        salt_2.push(((idx) & 0xff) as u8);
        let mut res_t = utils::hmac(digest, password.as_ref(), &[&salt_2])?;
        let mut res_u = res_t.clone();
        for _ in 0..iterations - 1 {
            res_u = utils::hmac(digest, password.as_ref(), &[&res_u])?;
            for k in 0..res_t.len() {
                res_t[k] ^= res_u[k];
            }
        }
        chunk.copy_from_slice(&res_t[..chunk.len()]);
    }
    Ok(out)
}

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
            self.b32[i] = ((self.xx[i * 4 + 0] & 0xff) as i32) << 0;
            self.b32[i] |= ((self.xx[i * 4 + 1] & 0xff) as i32) << 8;
            self.b32[i] |= ((self.xx[i * 4 + 2] & 0xff) as i32) << 16;
            self.b32[i] |= ((self.xx[i * 4 + 3] & 0xff) as i32) << 24;
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
            self.xx[i * 4 + 0] = (self.b32[i] >> 0 & 0xff) as u8;
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
    let f = pbkdf2(&password, &s, 1, keylen, "HMAC/SHA-256")?;
    Ok(f)
}

/// Equivalent to `crypto.Cipher`
///
/// `cipher.setAutoPadding` is unsupported current.
///
/// Example:
///
/// ```rust
/// use crate::Cipher;
///
/// let mut c = Cipher::create(alg, key, iv)?;
/// c.set_aad(aad)?; // optional
/// c.update(msg1)?;
/// c.update(msg2)?;
/// let res = c.fin()?;
/// let auth_tag = c.get_auth_tag()?;
/// ```
pub struct Cipher {
    handle: raw::SymmetricState,
    message: Vec<u8>,
    tag: Option<Vec<u8>>,
}

impl Cipher {
    /// Equivalent to `createCipheriv`
    ///
    /// For `AES-128-GCM` key should be 16 bytes and iv should be 12 bytes.
    /// For `AES-256-GCM` key should be 32 bytes and iv should be 12 bytes.
    /// For `CHACHA20-POLY1305` key should be 32 bytes and iv should be 12 bytes.
    pub fn create(
        alg: &str,
        key: impl AsRef<[u8]>,
        iv: impl AsRef<[u8]>,
    ) -> Result<Self, CryptoErrno> {
        let alg = match alg {
            "aes-128-gcm" | "AES-128-GCM" => "AES-128-GCM",
            "aes-256-gcm" | "AES-256-GCM" => "AES-256-GCM",
            "chacha20-poly1305" | "CHACHA20-POLY1305" => "CHACHA20-POLY1305",
            _ => return Err(raw::CRYPTO_ERRNO_UNSUPPORTED_ALGORITHM),
        };
        let handle = {
            let key = key.as_ref();
            let iv = iv.as_ref();
            unsafe {
                let raw_key = raw::symmetric_key_import(alg, key.as_ptr(), key.len())?;
                let key = raw::OptSymmetricKey {
                    tag: raw::OPT_SYMMETRIC_KEY_U_SOME.raw(),
                    u: raw::OptSymmetricKeyUnion { some: raw_key },
                };
                let opt = raw::options_open(raw::ALGORITHM_TYPE_SYMMETRIC)?;
                raw::options_set(opt, "nonce", iv.as_ptr(), iv.len())?;
                let opts = raw::OptOptions {
                    tag: raw::OPT_OPTIONS_U_SOME.raw(),
                    u: raw::OptOptionsUnion { some: opt },
                };
                let state = raw::symmetric_state_open(alg, key, opts)?;
                raw::symmetric_key_close(raw_key)?;
                state
            }
        };
        Ok(Self {
            handle,
            message: vec![],
            tag: None,
        })
    }

    /// Sets the value used for the additional authenticated data (AAD) input parameter.
    /// The `set_add` method must be called before `update`.
    pub fn set_aad(&mut self, data: impl AsRef<[u8]>) -> Result<(), CryptoErrno> {
        let data = data.as_ref();
        unsafe { raw::symmetric_state_absorb(self.handle, data.as_ptr(), data.len()) }
    }

    /// in WasmEdge implement of wasi-crypto, `encrypt` can't be called multiple times,
    /// multiple call `encrypt` is also not equivalent to multiple call `update`.
    /// so we store all message and concat it, then encrypt one-time on `fin`
    pub fn update(&mut self, data: impl AsRef<[u8]>) -> Result<(), CryptoErrno> {
        self.message.extend_from_slice(data.as_ref());
        Ok(())
    }

    /// `final` is reserved keyword, `fin` looks better than `r#final`
    pub fn fin(&mut self) -> Result<Vec<u8>, CryptoErrno> {
        let mut out = vec![0; self.message.len()];
        unsafe {
            let tag = raw::symmetric_state_encrypt_detached(
                self.handle,
                out.as_mut_ptr(),
                out.len(),
                self.message.as_ptr(),
                self.message.len(),
            )?;
            let len = raw::symmetric_tag_len(tag)?;
            let mut buf = vec![0; len];
            raw::symmetric_tag_pull(tag, buf.as_mut_ptr(), buf.len())?;
            raw::symmetric_tag_close(tag)?;
            self.tag = Some(buf);
        }
        Ok(out)
    }

    /// Equivalent to `update(data)` then `fin`, but no need to restore data in struct internal.
    pub fn encrypt(&mut self, data: impl AsRef<[u8]>) -> Result<Vec<u8>, CryptoErrno> {
        let data = data.as_ref();
        let mut out = vec![0; data.len()];
        unsafe {
            let tag = raw::symmetric_state_encrypt_detached(
                self.handle,
                out.as_mut_ptr(),
                out.len(),
                data.as_ptr(),
                data.len(),
            )?;
            let len = raw::symmetric_tag_len(tag)?;
            let mut buf = vec![0; len];
            raw::symmetric_tag_pull(tag, buf.as_mut_ptr(), buf.len())?;
            raw::symmetric_tag_close(tag)?;
            self.tag = Some(buf);
        }
        Ok(out)
    }

    /// The `get_auth_tag` method should only be called after encryption has been completed using the `fin` method.
    pub fn get_auth_tag(&self) -> Result<&Vec<u8>, CryptoErrno> {
        self.tag.as_ref().ok_or(raw::CRYPTO_ERRNO_INVALID_OPERATION)
    }

    /// As same as `get_auth_tag`, but get the ownership of `auth_tag` stored in struct internal.
    pub fn take_auth_tag(&mut self) -> Result<Vec<u8>, CryptoErrno> {
        self.tag.take().ok_or(raw::CRYPTO_ERRNO_INVALID_OPERATION)
    }
}

impl Drop for Cipher {
    fn drop(&mut self) {
        unsafe {
            raw::symmetric_state_close(self.handle).unwrap();
        }
    }
}

/// Equivalent to `crypto.Decipher`
///
/// Example:
///
/// ```rust
/// let mut d = Decipher::create(alg, key, iv)?;
/// d.set_aad(aad)?; // optional
/// d.set_auth_tag(auth_tag)?;
/// let src = d.decrypt(msg)?;
/// ```
pub struct Decipher {
    handle: raw::SymmetricState,
    message: Vec<u8>,
    tag: Option<Vec<u8>>,
}

impl Decipher {
    /// Equivalent to `createDecipheriv`
    ///
    /// For `AES-128-GCM` key should be 16 bytes and iv should be 12 bytes.
    /// For `AES-256-GCM` key should be 32 bytes and iv should be 12 bytes.
    /// For `CHACHA20-POLY1305` key should be 32 bytes and iv should be 12 bytes.
    pub fn create(
        alg: &str,
        key: impl AsRef<[u8]>,
        iv: impl AsRef<[u8]>,
    ) -> Result<Self, CryptoErrno> {
        let alg = match alg {
            "aes-128-gcm" | "AES-128-GCM" => "AES-128-GCM",
            "aes-256-gcm" | "AES-256-GCM" => "AES-256-GCM",
            "chacha20-poly1305" | "CHACHA20-POLY1305" => "CHACHA20-POLY1305",
            _ => return Err(raw::CRYPTO_ERRNO_UNSUPPORTED_ALGORITHM),
        };
        let handle = {
            let key = key.as_ref();
            let iv = iv.as_ref();
            unsafe {
                let raw_key = raw::symmetric_key_import(alg, key.as_ptr(), key.len())?;
                let key = raw::OptSymmetricKey {
                    tag: raw::OPT_SYMMETRIC_KEY_U_SOME.raw(),
                    u: raw::OptSymmetricKeyUnion { some: raw_key },
                };
                let opt = raw::options_open(raw::ALGORITHM_TYPE_SYMMETRIC)?;
                raw::options_set(opt, "nonce", iv.as_ptr(), iv.len())?;
                let opts = raw::OptOptions {
                    tag: raw::OPT_OPTIONS_U_SOME.raw(),
                    u: raw::OptOptionsUnion { some: opt },
                };
                let state = raw::symmetric_state_open(alg, key, opts)?;
                raw::symmetric_key_close(raw_key)?;
                state
            }
        };
        Ok(Self {
            handle,
            message: vec![],
            tag: None,
        })
    }

    /// Sets the value used for the additional authenticated data (AAD) input parameter.
    /// The `set_add` method must be called before `update`.
    pub fn set_aad(&mut self, data: impl AsRef<[u8]>) -> Result<(), CryptoErrno> {
        let data = data.as_ref();
        unsafe { raw::symmetric_state_absorb(self.handle, data.as_ptr(), data.len()) }
    }

    /// In WasmEdge implementation of wasi-crypto, `decrypt` can't be called multiple times,
    /// multiple call `decrypt` is also not equivalent to multiple call `update`.
    /// so we store all message and concat it, then decrypt one-time on `final`
    pub fn update(&mut self, data: impl AsRef<[u8]>) -> Result<(), CryptoErrno> {
        self.message.extend_from_slice(data.as_ref());
        Ok(())
    }

    /// `final` is reserved keyword, `fin` looks better than `r#final`
    pub fn fin(&mut self) -> Result<Vec<u8>, CryptoErrno> {
        if let Some(tag) = &self.tag {
            let mut out = vec![0; self.message.len()];
            unsafe {
                raw::symmetric_state_decrypt_detached(
                    self.handle,
                    out.as_mut_ptr(),
                    out.len(),
                    self.message.as_ptr(),
                    self.message.len(),
                    tag.as_ptr(),
                    tag.len(),
                )?;
            }
            Ok(out)
        } else {
            Err(raw::CRYPTO_ERRNO_INVALID_OPERATION)
        }
    }

    /// Equivalent to `update(data)` then `fin`, but no need to restore data in struct internal.
    pub fn decrypt(&mut self, data: impl AsRef<[u8]>) -> Result<Vec<u8>, CryptoErrno> {
        let data = data.as_ref();
        if let Some(tag) = &self.tag {
            let mut out = vec![0; data.len()];
            unsafe {
                raw::symmetric_state_decrypt_detached(
                    self.handle,
                    out.as_mut_ptr(),
                    out.len(),
                    data.as_ptr(),
                    data.len(),
                    tag.as_ptr(),
                    tag.len(),
                )?;
            }
            Ok(out)
        } else {
            Err(raw::CRYPTO_ERRNO_INVALID_OPERATION)
        }
    }

    /// When using an authenticated encryption mode (GCM are currently supported), the `set_auth_tag` method is used to pass in the received authentication tag.
    /// The `set_auth_tag` method must be called before `fin` for GCM modes.
    pub fn set_auth_tag(&mut self, data: impl AsRef<[u8]>) -> Result<(), CryptoErrno> {
        self.tag = Some(data.as_ref().to_vec());
        Ok(())
    }
}

impl Drop for Decipher {
    fn drop(&mut self) {
        unsafe {
            raw::symmetric_state_close(self.handle).unwrap();
        }
    }
}

pub struct PublicKey {
    handle: raw::Publickey
}

impl PublicKey {
    pub fn export(kind: &str, format: &str) -> Result<Vec<u8>, CryptoErrno> {
        // for ecdsa support bin-spki, pem-spki, bin-sec
        // for eddsa support bin-raw
        matches!(kind, "spki");
        matches!(format, "pem" | "der");
        todo!()
    }
}

pub struct SecretKey {
    handle: raw::Secretkey
}

impl SecretKey {
    pub fn export(kind: &str, format: &str, cipher: &str, passphrase: impl AsRef<[u8]>) -> Result<Vec<u8>, CryptoErrno> {
        // for ecdsa support bin-pkcs8, pem-pkcs8, bin-raw
        // for eddsa support bin-raw
        matches!(kind, "pkcs8" | "sec1");
        matches!(format, "pem" | "der");
        todo!()
    }
}
