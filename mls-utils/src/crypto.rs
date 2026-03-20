#[cfg(feature = "signatures")]
pub mod signatures {
    use crate::{NamedCiphersuite, UtilError};
    use mimi_protocol_mls::reexports::mls_spec::{Serializable, crypto::SignContent, defs::CiphersuiteId};

    #[cfg(feature = "keygen")]
    pub mod keygen {

        use mimi_protocol_mls::reexports::mls_spec::{
            crypto::{KeyPair, SignatureKeyPair},
            defs::CiphersuiteId,
        };

        use crate::{NamedCiphersuite, UtilError};

        pub fn generate_signature_keypair(cs: CiphersuiteId) -> Result<SignatureKeyPair, UtilError> {
            let named_cs = NamedCiphersuite::from(cs);

            let mut csprng = rand::thread_rng();

            Ok(match named_cs {
                NamedCiphersuite::Mls128DHKemX25519AesGcm128Sha256
                | NamedCiphersuite::Mls128DHKemX25519ChaCha20Poly1305Sha256 => {
                    let private_key = ed25519_dalek::SigningKey::generate(&mut csprng);
                    let public_key = private_key.verifying_key();
                    KeyPair {
                        ciphersuite: cs,
                        kem_id: named_cs.hpke_kem_id()?,
                        sk: private_key.to_bytes().to_vec().into(),
                        pk: public_key.to_bytes().to_vec().into(),
                    }
                    .into()
                }
                NamedCiphersuite::Mls128DHKemP256AesGcm128Sha256 => {
                    let private_key = p256::ecdsa::SigningKey::random(&mut csprng);
                    let public_key = private_key.verifying_key();
                    KeyPair {
                        ciphersuite: cs,
                        kem_id: named_cs.hpke_kem_id()?,
                        sk: private_key.to_bytes().to_vec().into(),
                        pk: public_key.to_sec1_bytes().into_vec().into(),
                    }
                    .into()
                }
                NamedCiphersuite::Mls256DHKemP384AesGcm256Sha384 => {
                    let private_key = p384::ecdsa::SigningKey::random(&mut csprng);
                    let public_key = private_key.verifying_key();
                    KeyPair {
                        ciphersuite: cs,
                        kem_id: named_cs.hpke_kem_id()?,
                        sk: private_key.to_bytes().to_vec().into(),
                        pk: public_key.to_sec1_bytes().into_vec().into(),
                    }
                    .into()
                }
                NamedCiphersuite::Mls256DHKemP521AesGcm256Sha512 => {
                    let private_key = p521::ecdsa::SigningKey::random(&mut csprng);
                    let public_key = p521::ecdsa::VerifyingKey::from(&private_key);
                    KeyPair {
                        ciphersuite: cs,
                        kem_id: named_cs.hpke_kem_id()?,
                        sk: private_key.to_bytes().to_vec().into(),
                        pk: public_key.to_encoded_point(false).to_bytes().to_vec().into(),
                    }
                    .into()
                }
                NamedCiphersuite::Unsupported(cs) => return Err(UtilError::UnsupportedCiphersuite(cs)),
                _ => return Err(UtilError::UnknownCiphersuite(cs)),
            })
        }
    }

    pub fn sk_to_pk(cs: CiphersuiteId, signature_private_key: &[u8]) -> Result<Vec<u8>, UtilError> {
        let named_cs = NamedCiphersuite::from(cs);

        match named_cs {
            NamedCiphersuite::Mls128DHKemX25519AesGcm128Sha256
            | NamedCiphersuite::Mls128DHKemX25519ChaCha20Poly1305Sha256 => {
                let sk = ed25519_dalek::SigningKey::from_bytes(&signature_private_key.try_into()?);
                let pk = sk.verifying_key();
                Ok(pk.to_bytes().to_vec())
            }
            NamedCiphersuite::Mls128DHKemP256AesGcm128Sha256 => {
                let sk = p256::ecdsa::SigningKey::from_bytes(signature_private_key.into())?;
                let pk = *sk.verifying_key();
                Ok(pk.to_sec1_bytes().into_vec())
            }
            NamedCiphersuite::Mls256DHKemP384AesGcm256Sha384 => {
                let sk = p384::ecdsa::SigningKey::from_bytes(signature_private_key.into())?;
                let pk = *sk.verifying_key();
                Ok(pk.to_sec1_bytes().into_vec())
            }
            NamedCiphersuite::Mls256DHKemP521AesGcm256Sha512 => {
                let sk = p521::ecdsa::SigningKey::from_bytes(signature_private_key.into())?;
                let pk = p521::ecdsa::VerifyingKey::from(&sk);
                Ok(pk.to_encoded_point(false).to_bytes().to_vec())
            }
            NamedCiphersuite::Unsupported(cs) => Err(UtilError::UnsupportedCiphersuite(cs)),
            _ => Err(UtilError::UnknownCiphersuite(cs)),
        }
    }

    pub fn verify_raw(
        signature_public_key: &[u8],
        cs: CiphersuiteId,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), UtilError> {
        use signature::Verifier as _;
        let cs = NamedCiphersuite::from(cs);

        match cs {
            NamedCiphersuite::Mls128DHKemX25519AesGcm128Sha256
            | NamedCiphersuite::Mls128DHKemX25519ChaCha20Poly1305Sha256 => {
                let verifying_key = ed25519_dalek::VerifyingKey::try_from(signature_public_key)
                    .map_err(|_| UtilError::InvalidSignature)?;

                let signature =
                    ed25519_dalek::Signature::from_slice(signature).map_err(|_| UtilError::InvalidSignature)?;

                verifying_key
                    .verify_strict(message, &signature)
                    .map_err(|_| UtilError::InvalidSignature)?;
            }
            NamedCiphersuite::Mls128DHKemP256AesGcm128Sha256 => {
                let verifying_key = p256::ecdsa::VerifyingKey::from_sec1_bytes(signature_public_key)
                    .map_err(|_| UtilError::InvalidSignature)?;
                let signature =
                    p256::ecdsa::DerSignature::from_bytes(signature).map_err(|_| UtilError::InvalidSignature)?;

                verifying_key
                    .verify(message, &signature)
                    .map_err(|_| UtilError::InvalidSignature)?;
            }
            NamedCiphersuite::Mls256DHKemP384AesGcm256Sha384 => {
                let verifying_key = p384::ecdsa::VerifyingKey::from_sec1_bytes(signature_public_key)
                    .map_err(|_| UtilError::InvalidSignature)?;
                let signature =
                    p384::ecdsa::DerSignature::from_bytes(signature).map_err(|_| UtilError::InvalidSignature)?;

                verifying_key
                    .verify(message, &signature)
                    .map_err(|_| UtilError::InvalidSignature)?;
            }
            NamedCiphersuite::Mls256DHKemP521AesGcm256Sha512 => {
                let verifying_key = p521::ecdsa::VerifyingKey::from_sec1_bytes(signature_public_key)
                    .map_err(|_| UtilError::InvalidSignature)?;
                let signature = p521::ecdsa::Signature::from_der(signature).map_err(|_| UtilError::InvalidSignature)?;

                verifying_key
                    .verify(message, &signature)
                    .map_err(|_| UtilError::InvalidSignature)?;
            }
            NamedCiphersuite::Unsupported(cs) => return Err(UtilError::UnsupportedCiphersuite(cs)),
            _ => return Err(UtilError::UnknownCiphersuite(cs.into())),
        }

        Ok(())
    }

    #[inline]
    pub fn verify_with_label(
        signature_public_key: &[u8],
        cs: CiphersuiteId,
        content: &[u8],
        label: &str,
        signature: &[u8],
    ) -> Result<(), UtilError> {
        verify_raw(
            signature_public_key,
            cs,
            &SignContent { content, label }.to_tls_bytes()?,
            signature,
        )
    }

    pub fn sign_raw(signature_private_key: &[u8], cs: CiphersuiteId, message: &[u8]) -> Result<Vec<u8>, UtilError> {
        use signature::Signer as _;
        let cs = NamedCiphersuite::from(cs);

        match cs {
            NamedCiphersuite::Mls128DHKemX25519AesGcm128Sha256
            | NamedCiphersuite::Mls128DHKemX25519ChaCha20Poly1305Sha256 => {
                let signature_key = ed25519_dalek::SigningKey::try_from(signature_private_key)?;
                let signature = signature_key.try_sign(message)?;

                Ok(signature.to_vec())
            }
            NamedCiphersuite::Mls128DHKemP256AesGcm128Sha256 => {
                let signature_key = p256::ecdsa::SigningKey::from_bytes(signature_private_key.into())?;

                let signature: p256::ecdsa::DerSignature = signature_key.try_sign(message)?;

                Ok(signature.to_bytes().to_vec())
            }
            NamedCiphersuite::Mls256DHKemP384AesGcm256Sha384 => {
                let signature_key = p384::ecdsa::SigningKey::from_bytes(signature_private_key.into())?;

                let signature: p384::ecdsa::DerSignature = signature_key.try_sign(message)?;

                Ok(signature.to_bytes().to_vec())
            }
            NamedCiphersuite::Mls256DHKemP521AesGcm256Sha512 => {
                let mut normalized_private_key = zeroize::Zeroizing::new([0u8; 66]);
                normalized_private_key[66 - signature_private_key.len()..].copy_from_slice(signature_private_key);
                let signature_key = p521::ecdsa::SigningKey::from_slice(signature_private_key)?;

                let signature: p521::ecdsa::DerSignature = signature_key.try_sign(message)?.to_der();

                Ok(signature.to_bytes().to_vec())
            }
            NamedCiphersuite::Unsupported(cs) => Err(UtilError::UnsupportedCiphersuite(cs)),
            _ => Err(UtilError::UnknownCiphersuite(cs.into())),
        }
    }

    #[inline]
    pub fn sign_with_label(
        signature_private_key: &[u8],
        cs: CiphersuiteId,
        content: &[u8],
        label: &str,
    ) -> Result<Vec<u8>, UtilError> {
        sign_raw(
            signature_private_key,
            cs,
            &SignContent { content, label }.to_tls_bytes()?,
        )
    }
}

#[cfg(feature = "pke")]
pub mod pke {
    use mimi_protocol_mls::reexports::mls_spec::{
        Serializable,
        crypto::{EncryptContext, HpkeCiphertext},
        defs::CiphersuiteId,
    };

    use crate::{NamedCiphersuite, UtilError};

    #[cfg(feature = "keygen")]
    pub mod keygen {
        use mimi_protocol_mls::reexports::mls_spec::{
            crypto::{HpkeKeyPair, KeyPair},
            defs::CiphersuiteId,
        };

        use crate::{NamedCiphersuite, UtilError};

        fn hpke_keygen<Kem: hpke::Kem>(ciphersuite: CiphersuiteId) -> HpkeKeyPair {
            use hpke::Serializable as _;
            let (sk, pk) = Kem::gen_keypair(&mut rand::thread_rng());
            KeyPair {
                kem_id: Kem::KEM_ID,
                ciphersuite,
                pk: pk.to_bytes().to_vec().into(),
                sk: sk.to_bytes().to_vec().into(),
            }
            .into()
        }

        pub fn generate_hpke_keypair(cs: CiphersuiteId) -> Result<HpkeKeyPair, UtilError> {
            let named_cs = NamedCiphersuite::from(cs);

            Ok(match named_cs {
                NamedCiphersuite::Mls128DHKemX25519AesGcm128Sha256
                | NamedCiphersuite::Mls128DHKemX25519ChaCha20Poly1305Sha256 => {
                    hpke_keygen::<hpke::kem::X25519HkdfSha256>(cs)
                }
                NamedCiphersuite::Mls128DHKemP256AesGcm128Sha256 => hpke_keygen::<hpke::kem::DhP256HkdfSha256>(cs),
                NamedCiphersuite::Mls256DHKemP384AesGcm256Sha384 => hpke_keygen::<hpke::kem::DhP384HkdfSha384>(cs),
                NamedCiphersuite::Mls256DHKemP521AesGcm256Sha512 => hpke_keygen::<hpke::kem::DhP521HkdfSha512>(cs),
                NamedCiphersuite::Unsupported(cs) => return Err(UtilError::UnsupportedCiphersuite(cs)),
                _ => return Err(UtilError::UnknownCiphersuite(cs)),
            })
        }
    }

    fn hpke_pk_from_sk<Kem: hpke::Kem>(private_key: &[u8]) -> Result<Vec<u8>, UtilError> {
        use hpke::{Deserializable as _, Serializable as _};

        let sk_len = <Kem::PrivateKey>::size();
        let mut normalized_private_key = zeroize::Zeroizing::new(vec![0u8; sk_len]);
        normalized_private_key[sk_len - private_key.len()..].copy_from_slice(private_key);
        let sk = Kem::PrivateKey::from_bytes(&normalized_private_key)?;
        let pk = Kem::sk_to_pk(&sk);
        Ok(pk.to_bytes().to_vec())
    }

    pub fn hpke_public_key_from_private_key(cs: CiphersuiteId, private_key: &[u8]) -> Result<Vec<u8>, UtilError> {
        let named_cs = NamedCiphersuite::from(cs);

        match named_cs {
            NamedCiphersuite::Mls128DHKemX25519AesGcm128Sha256
            | NamedCiphersuite::Mls128DHKemX25519ChaCha20Poly1305Sha256 => {
                hpke_pk_from_sk::<hpke::kem::X25519HkdfSha256>(private_key)
            }
            NamedCiphersuite::Mls128DHKemP256AesGcm128Sha256 => {
                hpke_pk_from_sk::<hpke::kem::DhP256HkdfSha256>(private_key)
            }
            NamedCiphersuite::Mls256DHKemP384AesGcm256Sha384 => {
                hpke_pk_from_sk::<hpke::kem::DhP384HkdfSha384>(private_key)
            }
            NamedCiphersuite::Mls256DHKemP521AesGcm256Sha512 => {
                hpke_pk_from_sk::<hpke::kem::DhP521HkdfSha512>(private_key)
            }
            NamedCiphersuite::Unsupported(cs) => Err(UtilError::UnsupportedCiphersuite(cs)),
            _ => Err(UtilError::UnknownCiphersuite(cs)),
        }
    }

    fn hpke_seal<Kem: hpke::Kem, Aead: hpke::aead::Aead, Kdf: hpke::kdf::Kdf>(
        public_key: &[u8],
        info: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<HpkeCiphertext, UtilError> {
        use hpke::{Deserializable as _, Serializable as _};
        let public_key = Kem::PublicKey::from_bytes(public_key)?;
        let (encapped, ciphertext) = hpke::single_shot_seal::<Aead, Kdf, Kem, _>(
            &hpke::OpModeS::Base,
            &public_key,
            info,
            plaintext,
            aad,
            &mut rand::thread_rng(),
        )?;

        Ok(HpkeCiphertext {
            kem_output: encapped.to_bytes().to_vec().into(),
            ciphertext: ciphertext.into(),
        })
    }

    fn hpke_open<Kem: hpke::Kem, Aead: hpke::aead::Aead, Kdf: hpke::kdf::Kdf>(
        private_key: &[u8],
        kem_output: &[u8],
        info: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, UtilError> {
        use hpke::Deserializable as _;
        let encapped_key = Kem::EncappedKey::from_bytes(kem_output)?;
        let private_key = Kem::PrivateKey::from_bytes(private_key)?;
        let plaintext = hpke::single_shot_open::<Aead, Kdf, Kem>(
            &hpke::OpModeR::Base,
            &private_key,
            &encapped_key,
            info,
            ciphertext,
            aad,
        )?;
        Ok(plaintext)
    }

    pub fn encrypt_with_label(
        cs: CiphersuiteId,
        public_key: &[u8],
        label: &str,
        context: &[u8],
        plaintext: &[u8],
    ) -> Result<HpkeCiphertext, UtilError> {
        let encrypt_context = EncryptContext { label, context };
        let info = encrypt_context.to_tls_bytes()?;

        let cs = NamedCiphersuite::from(cs);

        Ok(match cs {
            NamedCiphersuite::Mls128DHKemX25519AesGcm128Sha256 => {
                hpke_seal::<hpke::kem::X25519HkdfSha256, hpke::aead::AesGcm128, hpke::kdf::HkdfSha256>(
                    public_key, &info, b"", plaintext,
                )?
            }
            NamedCiphersuite::Mls128DHKemX25519ChaCha20Poly1305Sha256 => {
                hpke_seal::<hpke::kem::X25519HkdfSha256, hpke::aead::ChaCha20Poly1305, hpke::kdf::HkdfSha256>(
                    public_key, &info, b"", plaintext,
                )?
            }
            NamedCiphersuite::Mls128DHKemP256AesGcm128Sha256 => {
                hpke_seal::<hpke::kem::DhP256HkdfSha256, hpke::aead::AesGcm128, hpke::kdf::HkdfSha256>(
                    public_key, &info, b"", plaintext,
                )?
            }
            NamedCiphersuite::Mls256DHKemP521AesGcm256Sha512 => {
                hpke_seal::<hpke::kem::DhP521HkdfSha512, hpke::aead::AesGcm256, hpke::kdf::HkdfSha512>(
                    public_key, &info, b"", plaintext,
                )?
            }
            NamedCiphersuite::Mls256DHKemP384AesGcm256Sha384 => {
                hpke_seal::<hpke::kem::DhP384HkdfSha384, hpke::aead::AesGcm256, hpke::kdf::HkdfSha384>(
                    public_key, &info, b"", plaintext,
                )?
            }
            NamedCiphersuite::Unsupported(cs) => return Err(UtilError::UnsupportedCiphersuite(cs)),
            _ => return Err(UtilError::UnknownCiphersuite(cs.into())),
        })
    }

    pub fn decrypt_with_label(
        cs: CiphersuiteId,
        private_key: &[u8],
        label: &str,
        context: &[u8],
        kem_output: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, UtilError> {
        let encrypt_context = EncryptContext { label, context };
        let info = encrypt_context.to_tls_bytes()?;
        let cs = NamedCiphersuite::from(cs);

        Ok(match cs {
            NamedCiphersuite::Mls128DHKemX25519AesGcm128Sha256 => hpke_open::<
                hpke::kem::X25519HkdfSha256,
                hpke::aead::AesGcm128,
                hpke::kdf::HkdfSha256,
            >(
                private_key, kem_output, &info, b"", ciphertext
            )?,
            NamedCiphersuite::Mls128DHKemX25519ChaCha20Poly1305Sha256 => {
                hpke_open::<hpke::kem::X25519HkdfSha256, hpke::aead::ChaCha20Poly1305, hpke::kdf::HkdfSha256>(
                    private_key,
                    kem_output,
                    &info,
                    b"",
                    ciphertext,
                )?
            }
            NamedCiphersuite::Mls128DHKemP256AesGcm128Sha256 => hpke_open::<
                hpke::kem::DhP256HkdfSha256,
                hpke::aead::AesGcm128,
                hpke::kdf::HkdfSha256,
            >(
                private_key, kem_output, &info, b"", ciphertext
            )?,
            NamedCiphersuite::Mls256DHKemP521AesGcm256Sha512 => hpke_open::<
                hpke::kem::DhP521HkdfSha512,
                hpke::aead::AesGcm256,
                hpke::kdf::HkdfSha512,
            >(
                private_key, kem_output, &info, b"", ciphertext
            )?,
            NamedCiphersuite::Mls256DHKemP384AesGcm256Sha384 => hpke_open::<
                hpke::kem::DhP384HkdfSha384,
                hpke::aead::AesGcm256,
                hpke::kdf::HkdfSha384,
            >(
                private_key, kem_output, &info, b"", ciphertext
            )?,
            NamedCiphersuite::Unsupported(cs) => return Err(UtilError::UnsupportedCiphersuite(cs)),
            _ => return Err(UtilError::UnknownCiphersuite(cs.into())),
        })
    }
}
