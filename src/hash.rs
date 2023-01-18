use crate::{raw, CryptoErrno, NONE_KEY, NONE_OPTS};

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
