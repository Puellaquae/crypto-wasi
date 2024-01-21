use crate::{key::AlgoKind, raw, CryptoErrno, PrivateKey, PublicKey};

pub fn diffie_hellman(pk: &PublicKey, sk: &PrivateKey) -> Result<Vec<u8>, CryptoErrno> {
    if pk.algo == AlgoKind::X25519 {
        unsafe {
            let arr = raw::kx_dh(pk.handle, sk.handle)?;
            let len = raw::array_output_len(arr)?;
            let mut buf = vec![0u8; len];
            raw::array_output_pull(arr, buf.as_mut_ptr(), buf.len())?;
            Ok(buf)
        }
    } else {
        let npk = pk.cast_to_dh_key()?;
        let nsk = sk.cast_to_dh_key()?;
        unsafe {
            let arr = raw::kx_dh(npk.handle, nsk.handle)?;
            let len = raw::array_output_len(arr)?;
            let mut buf = vec![0u8; len];
            raw::array_output_pull(arr, buf.as_mut_ptr(), buf.len())?;
            Ok(buf)
        }
    }
}
