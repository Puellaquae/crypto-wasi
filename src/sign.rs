use crate::{
    raw::{self, SIGNATURE_ENCODING_DER},
    CryptoErrno, PrivateKey,
};

pub fn sign(datas: &[impl AsRef<[u8]>], key: &PrivateKey) -> Result<Vec<u8>, CryptoErrno> {
    unsafe {
        let state = raw::signature_state_open(key.keypair_handle)?;
        for data in datas {
            raw::signature_state_update(state, data.as_ref().as_ptr(), data.as_ref().len())?;
        }
        let sig = raw::signature_state_sign(state)?;
        let arr = raw::signature_export(sig, SIGNATURE_ENCODING_DER)?;
        let len = raw::array_output_len(arr)?;
        let mut buf = vec![0; len];
        raw::array_output_pull(arr, buf.as_mut_ptr(), buf.len())?;

        // the array got contains zero padding in end, which nodejs won't accept
        // so we truncate by der sequence size info
        let buf_real_len = 2 + (buf[1] as usize);
        buf.truncate(buf_real_len);

        raw::signature_close(sig)?;
        raw::signature_state_close(state)?;
        Ok(buf)
    }
}
