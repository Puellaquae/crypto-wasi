use crate::{raw, CryptoErrno};

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
