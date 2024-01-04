use crate::{raw, Cipheriv, Decipheriv, Hash, Hmac};

/// A simplified api to call and calculate hmac
///
/// Equivalent to
///
/// ```js
/// let hmac = createHmac(alg, key);
/// infos.forEach(info => hmac.update(info));
/// let return = hmac.digest();
/// ```
pub fn hmac(
    alg: &str,
    key: impl AsRef<[u8]>,
    infos: &[impl AsRef<[u8]>],
) -> Result<Vec<u8>, raw::CryptoErrno> {
    let mut hash = Hmac::create(alg, key)?;
    for info in infos {
        hash.update(info)?;
    }
    hash.digest()
}

/// A simplified api to call and calculate hash
///
/// Equivalent to
///
/// ```js
/// let hash = createHash(alg);
/// infos.forEach(info => hash.update(info));
/// let return = hash.digest();
/// ```
pub fn hash(alg: &str, infos: &[impl AsRef<[u8]>]) -> Result<Vec<u8>, raw::CryptoErrno> {
    let mut hash = Hash::create(alg)?;
    for info in infos {
        hash.update(info)?;
    }
    hash.digest()
}

/// A simplified api to call and calculate decipher
pub fn decrypt(
    alg: &str,
    key: impl AsRef<[u8]>,
    iv: impl AsRef<[u8]>,
    aad: impl AsRef<[u8]>,
    auth_tag: impl AsRef<[u8]>,
    msg: impl AsRef<[u8]>,
) -> Result<Vec<u8>, raw::CryptoErrno> {
    let mut c = Decipheriv::create(alg, key, iv)?;
    c.set_aad(aad)?;
    c.set_auth_tag(auth_tag)?;
    c.decrypt(msg)
}

/// A simplified api to call and calculate cipher
pub fn encrypt(
    alg: &str,
    key: impl AsRef<[u8]>,
    iv: impl AsRef<[u8]>,
    aad: impl AsRef<[u8]>,
    msg: impl AsRef<[u8]>,
) -> Result<(Vec<u8>, Vec<u8>), raw::CryptoErrno> {
    let mut c = Cipheriv::create(alg, key, iv)?;
    c.set_aad(aad)?;
    let out = c.encrypt(msg)?;
    let tag = c.take_auth_tag()?;
    Ok((out, tag))
}

/// Convert u8 array to hex string
///
/// Equivalent to `Buffer.from(arr).toString("hex")`
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

/// Convert hex string to u8 array
///
/// # Examples
///
/// ```
/// use crypto_wasi::hex_to_u8array;
///
/// assert_eq!(hex_to_u8array("01172d"), Some(vec![01, 23, 45]));
/// ```
pub fn hex_to_u8array(arr: &str) -> Option<Vec<u8>> {
    if arr.len() % 2 != 0 || arr.chars().any(|v| !v.is_ascii_hexdigit()) {
        return None;
    }

    fn hex_byte_to_u8(h: u8) -> u8 {
        match h {
            b'0'..=b'9' => h - b'0',
            b'a'..=b'f' => 10 + h - b'a',
            b'A'..=b'F' => 10 + h - b'A',
            _ => unreachable!(),
        }
    }

    Some(
        arr.as_bytes()
            .chunks(2)
            .map(|v| (hex_byte_to_u8(v[0]) << 4) + hex_byte_to_u8(v[1]))
            .collect(),
    )
}
