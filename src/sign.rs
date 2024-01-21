use crate::{
    key::{AlgoKind, CurveKind},
    raw::{
        self, CRYPTO_ERRNO_UNSUPPORTED_ALGORITHM, SIGNATURE_ENCODING_DER, SIGNATURE_ENCODING_RAW,
    },
    CryptoErrno, PrivateKey, PublicKey,
};

/*
    nodejs can't get digest kind from Ras and RsaPss key
*/

pub fn sign(datas: &[impl AsRef<[u8]>], key: &PrivateKey) -> Result<Vec<u8>, CryptoErrno> {
    unsafe {
        let state = raw::signature_state_open(key.keypair_handle)?;
        for data in datas {
            raw::signature_state_update(state, data.as_ref().as_ptr(), data.as_ref().len())?;
        }
        let sig = raw::signature_state_sign(state)?;
        let buf = match key.algo {
            AlgoKind::Ed | AlgoKind::Rsa(_, _) | AlgoKind::RsaPss(_, _) => {
                let arr = raw::signature_export(sig, SIGNATURE_ENCODING_RAW)?;
                let len = raw::array_output_len(arr)?;
                let mut buf = vec![0; len];
                raw::array_output_pull(arr, buf.as_mut_ptr(), buf.len())?;
                buf
            }
            AlgoKind::Ec(curve) => {
                // Ecdsa sign result is not unique

                // ECDSA_P384_SHA384 in WasmEdge's wasi-crypto implemention use sha256 as digest, should issue it
                if curve != CurveKind::Secp384r1 {
                    return Err(raw::CRYPTO_ERRNO_NOT_IMPLEMENTED);
                }
                let arr = raw::signature_export(sig, SIGNATURE_ENCODING_DER)?;
                let len = raw::array_output_len(arr)?;
                let mut buf = vec![0; len];
                raw::array_output_pull(arr, buf.as_mut_ptr(), buf.len())?;

                // the array got contains zero padding in end, which nodejs won't accept
                // so we truncate by der sequence size info
                let buf_real_len = 2 + (buf[1] as usize);
                buf.truncate(buf_real_len);

                buf
            }
            AlgoKind::X25519 => return Err(CRYPTO_ERRNO_UNSUPPORTED_ALGORITHM),
        };

        raw::signature_close(sig)?;
        raw::signature_state_close(state)?;
        Ok(buf)
    }
}

pub fn verify(
    datas: &[impl AsRef<[u8]>],
    key: &PublicKey,
    sig: impl AsRef<[u8]>,
) -> Result<bool, CryptoErrno> {
    unsafe {
        let state = raw::signature_verification_state_open(key.handle)?;
        for data in datas {
            raw::signature_verification_state_update(
                state,
                data.as_ref().as_ptr(),
                data.as_ref().len(),
            )?;
        }
        let signature_handle = raw::signature_import(
            key.algo.to_str(),
            sig.as_ref().as_ptr(),
            sig.as_ref().len(),
            if let AlgoKind::Ec(_) = key.algo {
                raw::SIGNATURE_ENCODING_DER
            } else {
                raw::SIGNATURE_ENCODING_RAW
            },
        )?;
        let res = raw::signature_verification_state_verify(state, signature_handle);
        let ret = if res.is_err_and(|e| e == raw::CRYPTO_ERRNO_VERIFICATION_FAILED) {
            Ok(false)
        } else {
            res.and_then(|()| Ok(true))
        };
        raw::signature_close(signature_handle)?;
        raw::signature_verification_state_close(state)?;
        ret
    }
}
