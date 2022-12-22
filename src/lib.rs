mod raw;

/// Behaviour like 
/// 
/// ```js
/// let hmac = createHmac(alg, key);
/// infos.forEach(info => hmac.update(info));
/// let return = hmac.digest();
/// ```
pub fn hmac(
    alg: &'static str,
    key: impl AsRef<[u8]>,
    infos: &[impl AsRef<[u8]>],
) -> Result<Vec<u8>, raw::CryptoErrno> {
    let key = key.as_ref();
    let hmac_alg = match alg {
        "sha256" | "SHA256" | "HMAC/SHA-256" => "HMAC/SHA-256",
        "sha512" | "SHA512" | "HMAC/SHA-512" => "HMAC/SHA-512",
        _ => unreachable!(),
    };
    unsafe {
        let none_opts = raw::OptOptions {
            tag: raw::OPT_OPTIONS_U_NONE.raw(),
            u: raw::OptOptionsUnion { none: () },
        };
        let hmac_key = raw::symmetric_key_import(hmac_alg, key.as_ptr(), key.len())?;
        let hmac_handle = raw::symmetric_state_open(
            hmac_alg,
            raw::OptSymmetricKey {
                tag: raw::OPT_SYMMETRIC_KEY_U_SOME.raw(),
                u: raw::OptSymmetricKeyUnion { some: hmac_key },
            },
            none_opts,
        )?;
        for info in infos {
            let info = info.as_ref();
            raw::symmetric_state_absorb(hmac_handle, info.as_ptr(), info.len())?;
        }
        let tag = raw::symmetric_state_squeeze_tag(hmac_handle)?;
        raw::symmetric_state_close(hmac_handle)?;
        raw::symmetric_key_close(hmac_key)?;
        let len = raw::symmetric_tag_len(tag)?;
        let mut out = vec![0; len];
        raw::symmetric_tag_pull(tag, out.as_mut_ptr(), out.len())?;
        raw::symmetric_tag_close(tag)?;
        Ok(out)
    }
}

/// As same as `hkdf`, but use hmac to manual expand
pub fn hkdf_hmac(
    alg: &'static str,
    key: impl AsRef<[u8]>,
    salt: impl AsRef<[u8]>,
    info: impl AsRef<[u8]>,
    key_len: usize,
) -> Result<Vec<u8>, raw::CryptoErrno> {
    let key = key.as_ref();
    let salt = salt.as_ref();
    let info = info.as_ref();
    let (extract_alg, expand_alg, hash_len) = match alg {
        "sha256" | "SHA256" => ("HKDF-EXTRACT/SHA-256", "HKDF-EXPAND/SHA-256", 32),
        "sha512" | "SHA512" => ("HKDF-EXTRACT/SHA-512", "HKDF-EXPAND/SHA-512", 64),
        _ => return Err(raw::CRYPTO_ERRNO_UNSUPPORTED_ALGORITHM),
    };
    let none_opts = raw::OptOptions {
        tag: raw::OPT_OPTIONS_U_NONE.raw(),
        u: raw::OptOptionsUnion { none: () },
    };
    let expand_key = unsafe {
        let extract_key = raw::symmetric_key_import(extract_alg, key.as_ptr(), key.len())?;
        let extract_handle = raw::symmetric_state_open(
            extract_alg,
            raw::OptSymmetricKey {
                tag: raw::OPT_SYMMETRIC_KEY_U_SOME.raw(),
                u: raw::OptSymmetricKeyUnion { some: extract_key },
            },
            none_opts,
        )?;
        raw::symmetric_state_absorb(extract_handle, salt.as_ptr(), salt.len())?;
        let expand_key = raw::symmetric_state_squeeze_key(extract_handle, expand_alg)?;
        raw::symmetric_state_close(extract_handle)?;
        let arr_out = raw::symmetric_key_export(expand_key)?;
        raw::symmetric_key_close(expand_key)?;
        let len = raw::array_output_len(arr_out)?;
        let mut buf = vec![0; len];
        raw::array_output_pull(arr_out, buf.as_mut_ptr(), buf.len())?;
        Ok(buf)
    }?;
    let mut out = vec![0; key_len];
    let mut last = [].as_slice();
    for (idx, chunk) in out.chunks_mut(hash_len).enumerate() {
        let counter = [idx as u8 + 1];
        chunk.clone_from_slice(&hmac(alg, &expand_key, &[last, info, &counter])?[..chunk.len()]);
        last = chunk;
    }
    Ok(out)
}

/// Behaviour like `crypto.hkdfSync`
pub fn hkdf(
    alg: &'static str,
    key: impl AsRef<[u8]>,
    salt: impl AsRef<[u8]>,
    info: impl AsRef<[u8]>,
    key_len: usize,
) -> Result<Vec<u8>, raw::CryptoErrno> {
    let key = key.as_ref();
    let salt = salt.as_ref();
    let info = info.as_ref();
    let (extract_alg, expand_alg) = match alg {
        "sha256" | "SHA256" => ("HKDF-EXTRACT/SHA-256", "HKDF-EXPAND/SHA-256"),
        "sha512" | "SHA512" => ("HKDF-EXTRACT/SHA-512", "HKDF-EXPAND/SHA-512"),
        _ => return Err(raw::CRYPTO_ERRNO_UNSUPPORTED_ALGORITHM),
    };
    let none_opts = raw::OptOptions {
        tag: raw::OPT_OPTIONS_U_NONE.raw(),
        u: raw::OptOptionsUnion { none: () },
    };
    let mut out = vec![0; key_len];
    unsafe {
        let extract_key = raw::symmetric_key_import(extract_alg, key.as_ptr(), key.len())?;
        let extract_handle = raw::symmetric_state_open(
            extract_alg,
            raw::OptSymmetricKey {
                tag: raw::OPT_SYMMETRIC_KEY_U_SOME.raw(),
                u: raw::OptSymmetricKeyUnion { some: extract_key },
            },
            none_opts,
        )?;
        raw::symmetric_state_absorb(extract_handle, salt.as_ptr(), salt.len())?;
        let expand_key = raw::symmetric_state_squeeze_key(extract_handle, expand_alg)?;
        raw::symmetric_state_close(extract_handle)?;
        raw::symmetric_key_close(extract_key)?;
        let expand_handle = raw::symmetric_state_open(
            expand_alg,
            raw::OptSymmetricKey {
                tag: raw::OPT_SYMMETRIC_KEY_U_SOME.raw(),
                u: raw::OptSymmetricKeyUnion { some: expand_key },
            },
            none_opts,
        )?;
        raw::symmetric_state_absorb(expand_handle, info.as_ptr(), info.len())?;
        raw::symmetric_state_squeeze(expand_handle, out.as_mut_ptr(), out.len())?;
        raw::symmetric_state_close(expand_handle)?;
        raw::symmetric_key_close(expand_key)?;
    }
    Ok(out)
}

/// Behaviour like `crypto.pbkdf2Sync`
pub fn pbkdf2(
    alg: &'static str,
    password: impl AsRef<[u8]>,
    salt: impl AsRef<[u8]>,
    iters: usize,
    key_len: usize,
) -> Result<Vec<u8>, raw::CryptoErrno> {
    let hash_len = match alg {
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
        let mut res_t = hmac(alg, password.as_ref(), &[&salt_2])?;
        let mut res_u = res_t.clone();
        for _ in 0..iters - 1 {
            res_u = hmac(alg, password.as_ref(), &[&res_u])?;
            for k in 0..res_t.len() {
                res_t[k] ^= res_u[k];
            }
        }
        chunk.copy_from_slice(&res_t[..chunk.len()]);
    }
    Ok(out)
}

/// Convert u8 array to hex string,
/// behaviour like `Buffer.from(arr).toString("hex")`
///
/// # Examples
///
/// ```
/// use crypto_wasi::u8array_to_hex;
///
/// assert_eq!(u8array_to_hex([01, 23, 45]), "01172d".to_string());
/// ```
pub fn u8array_to_hex(arr: impl AsRef<[u8]>) -> String {
    arr.as_ref()
        .iter()
        .map(|v| format!("{:02x}", v))
        .collect::<Vec<_>>()
        .join("")
}
