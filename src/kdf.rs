use crate::{raw, utils, CryptoErrno, NONE_OPTS};

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

/// As same as [hkdf], but use hmac to manual expand
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
/// Supported algorithm:
/// - SHA256
/// - SHA512
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
/// 
/// Supported algorithm:
/// - SHA256
/// - SHA512
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
