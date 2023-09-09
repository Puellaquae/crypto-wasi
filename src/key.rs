use crate::{raw, CryptoErrno, NONE_OPTS};
use base64::{engine::general_purpose::URL_SAFE, engine::general_purpose::URL_SAFE_NO_PAD, Engine};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum KeyEncodingFormat {
    Pem,
    Der,
    Jwk,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CurveKind {
    Prime256v1,
    Secp256k1,
    Secp384r1,
}

const OID_CURVE_PRIME256V1: &str = "1.2.840.10045.3.1.7";
const OID_CURVE_SECP256K1: &str = "1.3.132.0.10";
const OID_CURVE_SECP384R1: &str = "1.3.132.0.34";
const OID_ED25519: &str = "1.3.101.112";

#[derive(Clone, Copy, PartialEq, Eq)]
enum AlgoKind {
    Ed,
    Ec(CurveKind),
    Rsa(i32),
    RsaPss(i32),
}

impl AlgoKind {
    fn from_str(algo: &str) -> Result<Self, CryptoErrno> {
        let algo = algo.to_uppercase();
        let mut iter = algo.split('_');
        let a = iter.next();
        let b = iter.next();
        let c = iter.next();
        match (a, b, c) {
            (Some("ED25519"), _, _) => Ok(AlgoKind::Ed),
            (Some("ECDSA"), Some("P256"), _) => Ok(AlgoKind::Ec(CurveKind::Prime256v1)),
            (Some("ECDSA"), Some("K256"), _) => Ok(AlgoKind::Ec(CurveKind::Secp256k1)),
            (Some("ECDSA"), Some("P384"), _) => Ok(AlgoKind::Ec(CurveKind::Secp384r1)),
            (Some("RSA"), Some("PKCS1"), Some("2048")) => Ok(AlgoKind::Rsa(2048)),
            (Some("RSA"), Some("PKCS1"), Some("3072")) => Ok(AlgoKind::Rsa(3072)),
            (Some("RSA"), Some("PKCS1"), Some("4096")) => Ok(AlgoKind::Rsa(4096)),
            (Some("RSA"), Some("PSS"), Some("2048")) => Ok(AlgoKind::RsaPss(2048)),
            (Some("RSA"), Some("PSS"), Some("3072")) => Ok(AlgoKind::RsaPss(3072)),
            (Some("RSA"), Some("PSS"), Some("4096")) => Ok(AlgoKind::RsaPss(4096)),
            _ => Err(raw::CRYPTO_ERRNO_UNSUPPORTED_ALGORITHM),
        }
    }
}

/// WIP
pub struct PublicKey {
    pub handle: raw::Publickey,
    algo: AlgoKind,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PublicKeyEncodingType {
    Spki,
    Pkcs1,
}

fn publickey_export(
    pk: raw::Publickey,
    encoding: raw::PublickeyEncoding,
) -> Result<Vec<u8>, CryptoErrno> {
    let res = unsafe {
        let arr = raw::publickey_export(pk, encoding)?;
        let len = raw::array_output_len(arr)?;
        let mut buf = vec![0; len];
        raw::array_output_pull(arr, buf.as_mut_ptr(), buf.len())?;
        buf
    };
    Ok(res)
}

fn secretkey_export(
    sk: raw::Secretkey,
    encoding: raw::SecretkeyEncoding,
) -> Result<Vec<u8>, CryptoErrno> {
    let res = unsafe {
        let arr = raw::secretkey_export(sk, encoding)?;
        let len = raw::array_output_len(arr)?;
        let mut buf = vec![0; len];
        raw::array_output_pull(arr, buf.as_mut_ptr(), buf.len())?;
        buf
    };
    Ok(res)
}

impl PublicKey {
    pub fn export(
        &self,
        kind: PublicKeyEncodingType,
        format: KeyEncodingFormat,
    ) -> Result<Vec<u8>, CryptoErrno> {
        // for rsa, rsa-pss support der-spki(pkcs8), pem-spki(pem)
        // for ecdsa support der-spki(pkcs8), pem-spki(pem), bin-raw(sec)
        // for eddsa support bin-raw(raw)
        match (self.algo, kind, format) {
            (AlgoKind::Rsa(_), PublicKeyEncodingType::Spki, KeyEncodingFormat::Pem)
            | (AlgoKind::RsaPss(_), PublicKeyEncodingType::Spki, KeyEncodingFormat::Pem)
            | (AlgoKind::Ec(_), PublicKeyEncodingType::Spki, KeyEncodingFormat::Pem) => {
                publickey_export(self.handle, raw::PUBLICKEY_ENCODING_PEM)
            }
            (AlgoKind::Rsa(_), PublicKeyEncodingType::Spki, KeyEncodingFormat::Der)
            | (AlgoKind::RsaPss(_), PublicKeyEncodingType::Spki, KeyEncodingFormat::Der)
            | (AlgoKind::Ec(_), PublicKeyEncodingType::Spki, KeyEncodingFormat::Der) => {
                publickey_export(self.handle, raw::PUBLICKEY_ENCODING_PKCS8)
            }
            (AlgoKind::Ec(curve), _, KeyEncodingFormat::Jwk) => {
                let bin = publickey_export(self.handle, raw::PUBLICKEY_ENCODING_SEC)?;
                let compress_kind = bin[0];
                // rfc5480, sec1 2.3.3
                assert!(compress_kind == 0x04, "only support uncompressed form now");
                let x = URL_SAFE_NO_PAD.encode(&bin[1..33]);
                let y = URL_SAFE_NO_PAD.encode(&bin[33..65]);
                let curve_name = match curve {
                    CurveKind::Prime256v1 => "P-256",
                    CurveKind::Secp256k1 => "secp256k1",
                    CurveKind::Secp384r1 => "P-384",
                };
                let jwk = format!(r#"{{"x":"{x}","y":"{y}","kty":"EC","crv":"{curve_name}"}}"#);
                Ok(jwk.into_bytes())
            }
            (AlgoKind::Rsa(_), _, KeyEncodingFormat::Jwk) => {
                let der = publickey_export(self.handle, raw::PUBLICKEY_ENCODING_PKCS8)?;
                let raw = SubjectPublicKeyInfo::from_der(&der)
                    .unwrap()
                    .subject_public_key
                    .as_bytes()
                    .unwrap();
                let rsa_pk = RsaPublicKey::from_der(raw).unwrap();
                let n = URL_SAFE_NO_PAD.encode(rsa_pk.modulus.as_bytes());
                let e = URL_SAFE_NO_PAD.encode(rsa_pk.public_exponent.as_bytes());
                let jwk = format!(r#"{{"n":"{n}","e":"{e}","kty":"RSA"}}"#);
                Ok(jwk.into_bytes())
            }
            (AlgoKind::RsaPss(_), _, KeyEncodingFormat::Jwk) => {
                Err(raw::CRYPTO_ERRNO_UNSUPPORTED_ENCODING)
            }
            (AlgoKind::Ed, PublicKeyEncodingType::Spki, KeyEncodingFormat::Der)
            | (AlgoKind::Ed, PublicKeyEncodingType::Spki, KeyEncodingFormat::Pem) => {
                let raw = publickey_export(self.handle, raw::PUBLICKEY_ENCODING_RAW)?;
                let spki = SubjectPublicKeyInfo {
                    algorithm: AlgorithmIdentifier {
                        algorithm: ObjectIdentifier::new(OID_ED25519).unwrap(),
                        parameters: None,
                    },
                    subject_public_key: BitStringRef::new(0, &raw).unwrap(),
                };
                let der = spki.to_der().unwrap();
                match format {
                    KeyEncodingFormat::Der => Ok(der),
                    KeyEncodingFormat::Pem => Ok(pem::encode(&pem::Pem {
                        tag: "PUBLIC KEY".to_string(),
                        contents: der,
                    })
                    .into_bytes()),
                    KeyEncodingFormat::Jwk => unreachable!(),
                }
            }
            (AlgoKind::Ed, _, KeyEncodingFormat::Jwk) => {
                let raw = publickey_export(self.handle, raw::PUBLICKEY_ENCODING_RAW)?;
                let x = URL_SAFE.encode(raw);
                let jwk = format!(r#"{{"crv":"Ed25519","x":"{x}","kty":"OKP"}}"#);
                Ok(jwk.into_bytes())
            }
            (AlgoKind::Rsa(_), PublicKeyEncodingType::Pkcs1, KeyEncodingFormat::Pem)
            | (AlgoKind::Rsa(_), PublicKeyEncodingType::Pkcs1, KeyEncodingFormat::Der) => {
                let der = publickey_export(self.handle, raw::PUBLICKEY_ENCODING_PKCS8)?;
                let rsa_pk = SubjectPublicKeyInfo::from_der(&der)
                    .unwrap()
                    .subject_public_key
                    .as_bytes()
                    .unwrap();
                match format {
                    KeyEncodingFormat::Jwk => unreachable!(),
                    KeyEncodingFormat::Der => Ok(rsa_pk.to_vec()),
                    KeyEncodingFormat::Pem => Ok(pem::encode(&pem::Pem {
                        tag: "RSA PUBLIC KEY".to_string(),
                        contents: rsa_pk.to_vec(),
                    })
                    .into_bytes()),
                }
            }
            (_, PublicKeyEncodingType::Pkcs1, _) => Err(raw::CRYPTO_ERRNO_UNSUPPORTED_ENCODING),
        }
    }
}

/// WIP
pub struct PrivateKey {
    handle: raw::Secretkey,
    algo: AlgoKind,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PrivateKeyEncodingType {
    Pkcs8,
    Pkcs1,
    Sec1,
}

impl PrivateKey {
    fn get_publickey(&self) -> Result<PublicKey, CryptoErrno> {
        let pk = unsafe { raw::publickey_from_secretkey(self.handle) }?;
        Ok(PublicKey {
            handle: pk,
            algo: self.algo,
        })
    }

    pub fn export(
        &self,
        kind: PrivateKeyEncodingType,
        format: KeyEncodingFormat,
    ) -> Result<Vec<u8>, CryptoErrno> {
        // for rsa, rsa-pss support der-spki(pkcs8), pem-spki(pem)
        // for ecdsa support der-spki(pkcs8), pem-spki(pem), bin-raw(sec)
        // for eddsa support bin-raw(raw)
        match (self.algo, kind, format) {
            (
                AlgoKind::Ec(_) | AlgoKind::Rsa(_) | AlgoKind::RsaPss(_),
                PrivateKeyEncodingType::Pkcs8,
                KeyEncodingFormat::Pem,
            ) => secretkey_export(self.handle, raw::SECRETKEY_ENCODING_PEM),
            (
                AlgoKind::Rsa(_) | AlgoKind::RsaPss(_),
                PrivateKeyEncodingType::Pkcs8,
                KeyEncodingFormat::Der,
            ) => secretkey_export(self.handle, raw::SECRETKEY_ENCODING_PKCS8),
            // todo: ENCODING_PKCS8 on ecdsa get sec1-der actually
            (AlgoKind::Ec(_), PrivateKeyEncodingType::Pkcs8, KeyEncodingFormat::Der) => {
                let pem = secretkey_export(self.handle, raw::SECRETKEY_ENCODING_PEM)?;
                pem::parse(pem)
                    .or(Err(raw::CRYPTO_ERRNO_ALGORITHM_FAILURE))
                    .map(|p| p.contents)
            }
            (AlgoKind::Ec(curve), PrivateKeyEncodingType::Sec1, _)
            | (AlgoKind::Ec(curve), PrivateKeyEncodingType::Pkcs8, KeyEncodingFormat::Jwk) => {
                let res = secretkey_export(self.handle, raw::SECRETKEY_ENCODING_RAW)?;
                let curve = match curve {
                    CurveKind::Prime256v1 => OID_CURVE_PRIME256V1,
                    CurveKind::Secp256k1 => OID_CURVE_SECP256K1,
                    CurveKind::Secp384r1 => OID_CURVE_SECP384R1,
                };
                let pk = self.get_publickey()?;
                // the got is actually the public_key content in spki, not sure if it's a bug or feature
                let pk_data = publickey_export(pk.handle, raw::PUBLICKEY_ENCODING_SEC)?;
                let sec1 = EcPrivateKey {
                    private_key: &res,
                    parameters: Some(EcParameters::NamedCurve(curve.parse().unwrap())),
                    public_key: Some(&pk_data),
                };
                let der = sec1.to_der().unwrap();
                match format {
                    KeyEncodingFormat::Pem => Ok(pem::encode(&pem::Pem {
                        tag: "EC PRIVATE KEY".to_string(),
                        contents: der,
                    })
                    .into_bytes()),
                    KeyEncodingFormat::Der => Ok(der),
                    KeyEncodingFormat::Jwk => todo!(),
                }
            }
            (AlgoKind::Ed, PrivateKeyEncodingType::Pkcs8, _) => todo!(),
            (AlgoKind::Rsa(_), PrivateKeyEncodingType::Pkcs1, _) => todo!(),
            (AlgoKind::Rsa(_), PrivateKeyEncodingType::Pkcs8, KeyEncodingFormat::Jwk) => todo!(),
            (AlgoKind::RsaPss(_), PrivateKeyEncodingType::Pkcs8, KeyEncodingFormat::Jwk) => todo!(),
            _ => Err(raw::CRYPTO_ERRNO_UNSUPPORTED_ENCODING),
        }
    }
}

/// WIP
///
/// - "ECDSA_P256_SHA256" prime256v1
/// - "ECDSA_K256_SHA256" secp256k1
/// - "ECDSA_P384_SHA384" secp384r1
/// - "ED25519"
/// - "RSA_PKCS1_2048_SHA256"
/// - "RSA_PKCS1_2048_SHA384"
/// - "RSA_PKCS1_2048_SHA512"
/// - "RSA_PKCS1_3072_SHA384"
/// - "RSA_PKCS1_3072_SHA512"
/// - "RSA_PKCS1_4096_SHA512"
/// - "RSA_PSS_2048_SHA256"
/// - "RSA_PSS_2048_SHA384"
/// - "RSA_PSS_2048_SHA512"
/// - "RSA_PSS_3072_SHA384"
/// - "RSA_PSS_3072_SHA512"
/// - "RSA_PSS_4096_SHA512"
pub fn generate_key_pair(algorithm: &str) -> Result<(PublicKey, PrivateKey), CryptoErrno> {
    let algo = AlgoKind::from_str(algorithm)?;
    let (pk, sk) = unsafe {
        let kp = raw::keypair_generate(raw::ALGORITHM_TYPE_SIGNATURES, algorithm, NONE_OPTS)?;
        (raw::keypair_publickey(kp)?, raw::keypair_secretkey(kp)?)
    };
    Ok((
        PublicKey { handle: pk, algo },
        PrivateKey { handle: sk, algo },
    ))
}

use der::{
    asn1::{
        AnyRef, BitStringRef, ContextSpecific, ContextSpecificRef, ObjectIdentifier,
        OctetStringRef, UintRef,
    },
    Decode, DecodeValue, Encode, EncodeValue, FixedTag, Header, Length, Reader, Sequence, Tag,
    TagMode, TagNumber, Writer,
};

/// X.509 `AlgorithmIdentifier`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct AlgorithmIdentifier<'a> {
    /// This field contains an ASN.1 `OBJECT IDENTIFIER`, a.k.a. OID.
    pub algorithm: ObjectIdentifier,

    /// This field is `OPTIONAL` and contains the ASN.1 `ANY` type, which
    /// in this example allows arbitrary algorithm-defined parameters.
    pub parameters: Option<AnyRef<'a>>,
}

impl<'a> DecodeValue<'a> for AlgorithmIdentifier<'a> {
    fn decode_value<R: Reader<'a>>(reader: &mut R, _header: Header) -> der::Result<Self> {
        // The `der::Decoder::Decode` method can be used to decode any
        // type which impls the `Decode` trait, which is impl'd for
        // all of the ASN.1 built-in types in the `der` crate.
        //
        // Note that if your struct's fields don't contain an ASN.1
        // built-in type specifically, there are also helper methods
        // for all of the built-in types supported by this library
        // which can be used to select a specific type.
        //
        // For example, another way of decoding this particular field,
        // which contains an ASN.1 `OBJECT IDENTIFIER`, is by calling
        // `decoder.oid()`. Similar methods are defined for other
        // ASN.1 built-in types.
        let algorithm = reader.decode()?;

        // This field contains an ASN.1 `OPTIONAL` type. The `der` crate
        // maps this directly to Rust's `Option` type and provides
        // impls of the `Decode` and `Encode` traits for `Option`.
        // To explicitly request an `OPTIONAL` type be decoded, use the
        // `decoder.optional()` method.
        let parameters = reader.decode()?;

        // The value returned from the provided `FnOnce` will be
        // returned from the `any.sequence(...)` call above.
        // Note that the entire sequence body *MUST* be consumed
        // or an error will be returned.
        Ok(Self {
            algorithm,
            parameters,
        })
    }
}

impl<'a> ::der::EncodeValue for AlgorithmIdentifier<'a> {
    fn value_len(&self) -> ::der::Result<::der::Length> {
        self.algorithm.encoded_len()? + self.parameters.encoded_len()?
    }

    fn encode_value(&self, writer: &mut impl ::der::Writer) -> ::der::Result<()> {
        self.algorithm.encode(writer)?;
        self.parameters.encode(writer)?;
        Ok(())
    }
}

impl<'a> Sequence<'a> for AlgorithmIdentifier<'a> {}

/// X.509 `SubjectPublicKeyInfo` (SPKI)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct SubjectPublicKeyInfo<'a> {
    /// X.509 `AlgorithmIdentifier`
    algorithm: AlgorithmIdentifier<'a>,

    /// Public key data
    subject_public_key: BitStringRef<'a>,
}

impl<'a> DecodeValue<'a> for SubjectPublicKeyInfo<'a> {
    fn decode_value<R: Reader<'a>>(reader: &mut R, _header: Header) -> der::Result<Self> {
        let algorithm = reader.decode()?;
        let subject_public_key = reader.decode()?;
        Ok(Self {
            algorithm,
            subject_public_key,
        })
    }
}

impl<'a> EncodeValue for SubjectPublicKeyInfo<'a> {
    fn value_len(&self) -> der::Result<Length> {
        self.algorithm.encoded_len()? + self.subject_public_key.encoded_len()?
    }

    fn encode_value(&self, encoder: &mut impl Writer) -> der::Result<()> {
        self.algorithm.encode(encoder)?;
        self.subject_public_key.encode(encoder)
    }
}

impl<'a> Sequence<'a> for SubjectPublicKeyInfo<'a> {}

/// Elliptic curve parameters as described in
/// [RFC5480 Section 2.1.1](https://datatracker.ietf.org/doc/html/rfc5480#section-2.1.1):
///
/// ```text
/// ECParameters ::= CHOICE {
///   namedCurve         OBJECT IDENTIFIER
///   -- implicitCurve   NULL
///   -- specifiedCurve  SpecifiedECDomain
/// }
///   -- implicitCurve and specifiedCurve MUST NOT be used in PKIX.
///   -- Details for SpecifiedECDomain can be found in [X9.62].
///   -- Any future additions to this CHOICE should be coordinated
///   -- with ANSI X9.
/// ```
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum EcParameters {
    /// Elliptic curve named by a particular OID.
    ///
    /// > namedCurve identifies all the required values for a particular
    /// > set of elliptic curve domain parameters to be represented by an
    /// > object identifier.
    NamedCurve(ObjectIdentifier),
}

impl<'a> DecodeValue<'a> for EcParameters {
    fn decode_value<R: Reader<'a>>(decoder: &mut R, header: Header) -> der::Result<Self> {
        ObjectIdentifier::decode_value(decoder, header).map(Self::NamedCurve)
    }
}

impl FixedTag for EcParameters {
    const TAG: Tag = Tag::ObjectIdentifier;
}

impl EncodeValue for EcParameters {
    fn value_len(&self) -> der::Result<Length> {
        match self {
            Self::NamedCurve(oid) => oid.value_len(),
        }
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        match self {
            Self::NamedCurve(oid) => oid.encode_value(writer),
        }
    }
}

/// SEC1 elliptic curve private key.
///
/// Described in [SEC1: Elliptic Curve Cryptography (Version 2.0)]
/// Appendix C.4 (p.108) and also [RFC5915 Section 3]:
///
/// ```text
/// ECPrivateKey ::= SEQUENCE {
///   version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
///   privateKey     OCTET STRING,
///   parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
///   publicKey  [1] BIT STRING OPTIONAL
/// }
/// ```
///
/// When encoded as PEM (text), keys in this format begin with the following:
///
/// ```text
/// -----BEGIN EC PRIVATE KEY-----
/// ```
///
/// [SEC1: Elliptic Curve Cryptography (Version 2.0)]: https://www.secg.org/sec1-v2.pdf
/// [RFC5915 Section 3]: https://datatracker.ietf.org/doc/html/rfc5915#section-3
#[derive(Clone)]
struct EcPrivateKey<'a> {
    /// Private key data.
    private_key: &'a [u8],

    /// Elliptic curve parameters.
    parameters: Option<EcParameters>,

    /// Public key data, optionally available if version is V2.
    public_key: Option<&'a [u8]>,
}

/// `ECPrivateKey` version.
///
/// From [RFC5913 Section 3]:
/// > version specifies the syntax version number of the elliptic curve
/// > private key structure.  For this version of the document, it SHALL
/// > be set to ecPrivkeyVer1, which is of type INTEGER and whose value
/// > is one (1).
///
/// [RFC5915 Section 3]: https://datatracker.ietf.org/doc/html/rfc5915#section-3
const VERSION: u8 = 1;

/// Context-specific tag number for the elliptic curve parameters.
const EC_PARAMETERS_TAG: TagNumber = TagNumber::new(0);

/// Context-specific tag number for the public key.
const PUBLIC_KEY_TAG: TagNumber = TagNumber::new(1);

impl<'a> DecodeValue<'a> for EcPrivateKey<'a> {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
        reader.read_nested(header.length, |reader| {
            if u8::decode(reader)? != VERSION {
                return Err(der::Tag::Integer.value_error());
            }

            let private_key = OctetStringRef::decode(reader)?.as_bytes();
            let parameters = reader.context_specific(EC_PARAMETERS_TAG, TagMode::Explicit)?;
            let public_key = reader
                .context_specific::<BitStringRef<'_>>(PUBLIC_KEY_TAG, TagMode::Explicit)?
                .map(|bs| bs.as_bytes().ok_or_else(|| Tag::BitString.value_error()))
                .transpose()?;

            Ok(EcPrivateKey {
                private_key,
                parameters,
                public_key,
            })
        })
    }
}

impl<'a> EcPrivateKey<'a> {
    fn context_specific_parameters(&self) -> Option<ContextSpecificRef<'_, EcParameters>> {
        self.parameters.as_ref().map(|params| ContextSpecificRef {
            tag_number: EC_PARAMETERS_TAG,
            tag_mode: TagMode::Explicit,
            value: params,
        })
    }

    fn context_specific_public_key(
        &self,
    ) -> der::Result<Option<ContextSpecific<BitStringRef<'a>>>> {
        self.public_key
            .map(|pk| {
                BitStringRef::from_bytes(pk).map(|value| ContextSpecific {
                    tag_number: PUBLIC_KEY_TAG,
                    tag_mode: TagMode::Explicit,
                    value,
                })
            })
            .transpose()
    }
}

impl<'a> EncodeValue for EcPrivateKey<'a> {
    fn value_len(&self) -> der::Result<Length> {
        VERSION.encoded_len()?
            + OctetStringRef::new(self.private_key)?.encoded_len()?
            + self.context_specific_parameters().encoded_len()?
            + self.context_specific_public_key()?.encoded_len()?
    }

    fn encode_value(&self, encoder: &mut impl Writer) -> der::Result<()> {
        VERSION.encode(encoder)?;
        OctetStringRef::new(self.private_key)?.encode(encoder)?;
        self.context_specific_parameters().encode(encoder)?;
        self.context_specific_public_key()?.encode(encoder)
    }
}

impl<'a> Sequence<'a> for EcPrivateKey<'a> {}

/// PKCS#1 RSA Public Keys as defined in [RFC 8017 Appendix 1.1].
///
/// ASN.1 structure containing a serialized RSA public key:
///
/// ```text
/// RSAPublicKey ::= SEQUENCE {
///     modulus           INTEGER,  -- n
///     publicExponent    INTEGER   -- e
/// }
/// ```
///
/// [RFC 8017 Appendix 1.1]: https://datatracker.ietf.org/doc/html/rfc8017#appendix-A.1.1
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct RsaPublicKey<'a> {
    /// `n`: RSA modulus
    pub modulus: UintRef<'a>,

    /// `e`: RSA public exponent
    pub public_exponent: UintRef<'a>,
}

impl<'a> DecodeValue<'a> for RsaPublicKey<'a> {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
        reader.read_nested(header.length, |reader| {
            Ok(Self {
                modulus: reader.decode()?,
                public_exponent: reader.decode()?,
            })
        })
    }
}

impl EncodeValue for RsaPublicKey<'_> {
    fn value_len(&self) -> der::Result<Length> {
        self.modulus.encoded_len()? + self.public_exponent.encoded_len()?
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        self.modulus.encode(writer)?;
        self.public_exponent.encode(writer)?;
        Ok(())
    }
}

impl<'a> Sequence<'a> for RsaPublicKey<'a> {}
