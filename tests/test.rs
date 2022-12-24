use crypto_wasi::{hkdf, hkdf_hmac, hmac, pbkdf2, scrypt, u8array_to_hex};

#[test]
fn test_hkdf() {
    let cases256 = [(
        "sha256",
        "secret",
        "salt",
        "info",
        64,
        "f6d2fcc47cb939deafe3853a1e641a27e6924aff7a63d09cb04ccfffbe4776efdda39ae362b1346092d8cb4ee3f0ea74b84000e40066194ffca55d2128aa6c1a",
    ),
    (
        "sha256",
        "secret",
        "salt",
        "info",
        32,
        "f6d2fcc47cb939deafe3853a1e641a27e6924aff7a63d09cb04ccfffbe4776ef",
    ),
    (
        "sha256",
        "",
        "",
        "",
        32,
        "eb70f01dede9afafa449eee1b1286504e1f62388b3f7dd4f956697b0e828fe18",
    ),
    (
        "sha256",
        "",
        "",
        "",
        48,
        "eb70f01dede9afafa449eee1b1286504e1f62388b3f7dd4f956697b0e828fe181e59c2ec0fe6e7e7ac2613b6ab65342a",
    )];
    for (digest, key, salt, info, key_len, execpt) in cases256 {
        if key_len == 32 {
            assert_eq!(
                hkdf(digest, key, salt, info, key_len).map(u8array_to_hex),
                Ok(execpt.to_string())
            );
        }
        assert_eq!(
            hkdf_hmac(digest, key, salt, info, key_len).map(u8array_to_hex),
            Ok(execpt.to_string())
        );
    }

    let cases512 = [(
        "sha512",
        b"secret",
        b"salt",
        b"",
        128,
        "683045181e6325bbd2a5ba7fc5cecc3bf0d9bfe0963c3943867cf19c2b5de335faf87a0ad2a75688c78f63dc812a3c5d3ce29ed20ddadaf0edfb985789c66c9077c77c510e1806d3a8affb05d18e3d4c428afcadc968e80c50da7072da4ef446d1c28c6e3facba31809575fe74796cf4fde7238d9cc666b83ec08a0c5125bc9e",
    ),
    (
        "sha512",
        b"secret",
        b"salt",
        b"",
        64,
        "683045181e6325bbd2a5ba7fc5cecc3bf0d9bfe0963c3943867cf19c2b5de335faf87a0ad2a75688c78f63dc812a3c5d3ce29ed20ddadaf0edfb985789c66c90",
    )];
    for (digest, key, salt, info, key_len, execpt) in cases512 {
        if key_len == 64 {
            assert_eq!(
                hkdf(digest, key, salt, info, key_len).map(u8array_to_hex),
                Ok(execpt.to_string())
            );
        }
        assert_eq!(
            hkdf_hmac(digest, key, salt, info, key_len).map(u8array_to_hex),
            Ok(execpt.to_string())
        );
    }
}

#[test]
fn test_pbkdf2() {
    let cases = [
        (
            "password",
            "salt",
            1,
            20,
            "120fb6cffcf8b32c43e7225256c4f837a86548c9",
        ),
        (
            "password",
            "salt",
            2,
            20,
            "ae4d0c95af6b46d32d0adff928f06dd02a303f8e",
        ),
        (
            "password",
            "salt",
            4096,
            20,
            "c5e478d59288c841aa530db6845c4c8d962893a0",
        ),
        (
            "passwordPASSWORDpassword",
            "saltSALTsaltSALTsaltSALTsaltSALTsalt",
            4096,
            25,
            "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c",
        ),
        (
            "pass\0word",
            "sa\0lt",
            4096,
            16,
            "89b69d0516f829893c696226650a8687",
        ),
        (
            "password",
            "salt",
            32,
            32,
            "64c486c55d30d4c5a079b8823b7d7cb37ff0556f537da8410233bcec330ed956",
        ),
    ];
    for (password, salt, iters, key_len, except) in cases {
        assert_eq!(
            pbkdf2("sha256", password, salt, iters, key_len).map(u8array_to_hex),
            Ok(except.to_string())
        );
    }
}

#[test]
fn test_hmac() {
    let cases = [
        (
            "key",
            "The quick brown fox jumps over the lazy dog",
            "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8",
        ),
        (
            "key",
            "",
            "5d5d139563c95b5967b9bd9a8c9b233a9dedb45072794cd232dc1b74832607d0",
        ),
        (
            "",
            "The quick brown fox jumps over the lazy dog",
            "fb011e6154a19b9a4c767373c305275a5a69e8b68b0b4c9200c383dced19a416",
        ),
        (
            "",
            "",
            "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad",
        ),
    ];
    for (key, info, except) in cases {
        assert_eq!(
            hmac("sha256", key, &[info]).map(u8array_to_hex),
            Ok(except.to_string())
        );
    }
    assert_eq!(
        hmac(
            "sha256",
            b"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
            &[b"\x48\x69\x20\x54\x68\x65\x72\x65"]
        )
        .map(u8array_to_hex),
        Ok("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7".to_string())
    );
    assert_eq!(
        hmac(
            "sha512",
            b"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
            &[b"\x48\x69\x20\x54\x68\x65\x72\x65"]
        )
        .map(u8array_to_hex),
        Ok("87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854".to_string())
    );
}

#[test]
fn test_scrypt() {
    let cases = [
        (
            "",
            "",
            64,
            16,
            1,
            1,
            "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906",
        ),
        (
            "password",
            "NaCl",
            64,
            1024,
            16,
            8,
            "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640",
        ),
        (
            "pleaseletmein",
            "SodiumChloride",
            64,
            16384,
            1,
            8,
            "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887",
        ),
        (
            "",
            "",
            64,
            16,
            1,
            1,
            "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906",
        ),
        (
            "password",
            "NaCl",
            64,
            1024,
            16,
            8,
            "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640",
        ),
        (
            "pleaseletmein",
            "SodiumChloride",
            64,
            16384,
            1,
            8,
            "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887",
        ),
    ];
    for (password, salt, key_len, n, p, r, except) in cases {
        assert_eq!(
            scrypt(password, salt, n, r, p, key_len).map(u8array_to_hex),
            Ok(except.to_string())
        );
    }
}
