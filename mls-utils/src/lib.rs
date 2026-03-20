use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use meet_identifiers::GroupId;
use mimi_protocol_mls::reexports::mls_spec::{
    MlsSpecError, Serializable,
    crypto::HashReferenceInput,
    defs::{CiphersuiteId, ProposalType, WireFormat},
    key_package::KeyPackage,
    messages::{AuthenticatedContentRef, MlsMessage, MlsMessageContent},
};
use sha2::digest::{FixedOutput, crypto_common::KeySizeUser};

pub mod reexports {
    #[cfg(feature = "mls-rs")]
    pub use mls_rs;
    #[cfg(feature = "mls-rs")]
    pub use mls_rs_core;
    #[cfg(feature = "mls-rs")]
    pub use mls_rs_crypto_rustcrypto;
}

pub mod crypto;
pub mod transcript_hashes;
pub mod tree;

#[cfg(feature = "validations")]
pub mod validations;

#[derive(Debug, thiserror::Error)]
pub enum UtilError {
    #[error(transparent)]
    MlsSpecError(#[from] MlsSpecError),
    #[error(transparent)]
    BaseDecode58Error(#[from] bs58::decode::Error),
    #[error("Cannot create reference as the ciphersuite {0} is unknown")]
    UnknownCiphersuite(CiphersuiteId),
    #[error("The Ciphersuite is not supported yet")]
    UnsupportedCiphersuite(CiphersuiteId),
    #[error("No known hash algorithm from this ciphersuite {0:?}")]
    UnsupportedHashAlg(NamedCiphersuite),
    #[error("The {0} WireFormat is not yet supported")]
    UnsupportedWireFormat(WireFormat),
    #[error("Invalid UTF-8: {0}")]
    Utf8Error(#[from] std::string::FromUtf8Error),
    #[error("The Key for the Hmac alg {alg:?} has an invalid length, expected {expected}, got {actual}")]
    InvalidHmacKey {
        alg: HashAlg,
        expected: usize,
        actual: usize,
    },
    #[error(transparent)]
    RngError(#[from] rand::Error),
    #[error(transparent)]
    TryFromSliceError(#[from] std::array::TryFromSliceError),
    #[error("The API has been misused. This is an implementation error and must not happen: {0}")]
    ApiMisuse(&'static str),
    #[error("The MLS Message has the wrong ContentType or the message has no ContentType")]
    InvalidOrMissingContentType,
    #[error("Cannot find an ExternalSender in this GroupContext that matches our Signing Key")]
    ExternalSenderNotFound,
    #[error("The ProposalType {0} is not allowed in External Proposals")]
    ProposalTypeInvalidInExternalProposal(ProposalType),
    #[cfg(feature = "validations")]
    #[error(transparent)]
    ValidationError(#[from] validations::ValidationError),
    #[cfg(feature = "signatures")]
    #[error("The signature couldn't be verified")]
    InvalidSignature,
    #[cfg(feature = "signatures")]
    #[error("There was an error in the signing process: {0}")]
    #[cfg(feature = "signatures")]
    SignatureError(#[from] signature::Error),
    #[cfg(feature = "pke")]
    #[error(transparent)]
    HpkeError(#[from] hpke::HpkeError),
}

pub type UtilResult<T> = Result<T, UtilError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum NamedCiphersuite {
    Mls128DHKemX25519AesGcm128Sha256 = CiphersuiteId::MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519,
    Mls128DHKemP256AesGcm128Sha256 = CiphersuiteId::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
    Mls128DHKemX25519ChaCha20Poly1305Sha256 = CiphersuiteId::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519,
    Mls256DHKemX448AesGcm256Sha12 = CiphersuiteId::MLS_256_DHKEMX448_AES256GCM_SHA512_ED448,
    Mls256DHKemP521AesGcm256Sha512 = CiphersuiteId::MLS_256_DHKEMP521_AES256GCM_SHA512_P521,
    Mls256DHKemX448ChaCha20Poly1305Sha512 = CiphersuiteId::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_ED448,
    Mls256DHKemP384AesGcm256Sha384 = CiphersuiteId::MLS_256_DHKEMP384_AES256GCM_SHA384_P384,
    Unsupported(CiphersuiteId),
    Unknown(CiphersuiteId),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HashAlg {
    Sha256 = 1,
    Sha384 = 2,
    Sha512 = 3,
}

impl NamedCiphersuite {
    pub fn hash_alg(&self) -> Result<HashAlg, UtilError> {
        Ok(match self {
            NamedCiphersuite::Mls128DHKemX25519AesGcm128Sha256 => HashAlg::Sha256,
            NamedCiphersuite::Mls128DHKemP256AesGcm128Sha256 => HashAlg::Sha256,
            NamedCiphersuite::Mls128DHKemX25519ChaCha20Poly1305Sha256 => HashAlg::Sha256,
            NamedCiphersuite::Mls256DHKemX448AesGcm256Sha12 => HashAlg::Sha512,
            NamedCiphersuite::Mls256DHKemP521AesGcm256Sha512 => HashAlg::Sha512,
            NamedCiphersuite::Mls256DHKemX448ChaCha20Poly1305Sha512 => HashAlg::Sha512,
            NamedCiphersuite::Mls256DHKemP384AesGcm256Sha384 => HashAlg::Sha384,
            _ => return Err(UtilError::UnsupportedHashAlg(*self)),
        })
    }

    pub fn hpke_kem_id(&self) -> Result<u16, UtilError> {
        Ok(match self {
            NamedCiphersuite::Mls128DHKemX25519AesGcm128Sha256
            | NamedCiphersuite::Mls128DHKemX25519ChaCha20Poly1305Sha256 => 0x0020,
            NamedCiphersuite::Mls128DHKemP256AesGcm128Sha256 => 0x0010,
            NamedCiphersuite::Mls256DHKemP521AesGcm256Sha512 => 0x0012,
            NamedCiphersuite::Mls256DHKemP384AesGcm256Sha384 => 0x0011,
            _ => return Err(UtilError::UnsupportedCiphersuite((*self).into())),
        })
    }
}

impl HashAlg {
    pub fn digest(&self, input: &[u8]) -> Vec<u8> {
        use sha2::Digest as _;
        match self {
            HashAlg::Sha256 => sha2::Sha256::digest(input).to_vec(),
            HashAlg::Sha384 => sha2::Sha384::digest(input).to_vec(),
            HashAlg::Sha512 => sha2::Sha512::digest(input).to_vec(),
        }
    }

    pub fn digest_multi(&self, inputs: &[&[u8]]) -> Vec<u8> {
        use sha2::Digest as _;
        match self {
            HashAlg::Sha256 => {
                let mut hasher = sha2::Sha256::new();
                for input in inputs {
                    hasher.update(input);
                }
                hasher.finalize().to_vec()
            }
            HashAlg::Sha384 => {
                let mut hasher = sha2::Sha384::new();
                for input in inputs {
                    hasher.update(input);
                }
                hasher.finalize().to_vec()
            }
            HashAlg::Sha512 => {
                let mut hasher = sha2::Sha512::new();
                for input in inputs {
                    hasher.update(input);
                }
                hasher.finalize().to_vec()
            }
        }
    }

    pub fn hmac_key_gen(&self) -> UtilResult<Vec<u8>> {
        use rand::Fill as _;

        let key_size = match self {
            HashAlg::Sha256 => hmac::SimpleHmac::<sha2::Sha256>::key_size(),
            HashAlg::Sha384 => hmac::SimpleHmac::<sha2::Sha384>::key_size(),
            HashAlg::Sha512 => hmac::SimpleHmac::<sha2::Sha512>::key_size(),
        };

        let mut key = vec![0u8; key_size];
        key.try_fill(&mut rand::thread_rng())?;

        debug_assert_ne!(key, vec![0u8; key_size], "RNG didn't do its job, wrong API usage");

        Ok(key)
    }

    pub fn hmac(&self, key: &[u8], inputs: &[&[u8]]) -> UtilResult<Vec<u8>> {
        use hmac::Mac as _;
        match self {
            HashAlg::Sha256 => {
                let mut mac =
                    <hmac::SimpleHmac<sha2::Sha256> as hmac::digest::KeyInit>::new_from_slice(key).map_err(|_| {
                        UtilError::InvalidHmacKey {
                            alg: *self,
                            expected: hmac::SimpleHmac::<sha2::Sha256>::key_size(),
                            actual: key.len(),
                        }
                    })?;
                for input in inputs {
                    mac.update(input);
                }

                Ok(mac.finalize_fixed().to_vec())
            }
            HashAlg::Sha384 => {
                let mut mac =
                    <hmac::SimpleHmac<sha2::Sha384> as hmac::digest::KeyInit>::new_from_slice(key).map_err(|_| {
                        UtilError::InvalidHmacKey {
                            alg: *self,
                            expected: hmac::SimpleHmac::<sha2::Sha384>::key_size(),
                            actual: key.len(),
                        }
                    })?;
                for input in inputs {
                    mac.update(input);
                }

                Ok(mac.finalize_fixed().to_vec())
            }
            HashAlg::Sha512 => {
                let mut mac =
                    <hmac::SimpleHmac<sha2::Sha512> as hmac::digest::KeyInit>::new_from_slice(key).map_err(|_| {
                        UtilError::InvalidHmacKey {
                            alg: *self,
                            expected: hmac::SimpleHmac::<sha2::Sha512>::key_size(),
                            actual: key.len(),
                        }
                    })?;
                for input in inputs {
                    mac.update(input);
                }

                Ok(mac.finalize_fixed().to_vec())
            }
        }
    }

    pub fn hmac_verify(&self, key: &[u8], inputs: &[&[u8]], tag: &[u8]) -> UtilResult<bool> {
        use hmac::Mac as _;
        match self {
            HashAlg::Sha256 => {
                let mut mac =
                    <hmac::SimpleHmac<sha2::Sha256> as hmac::digest::KeyInit>::new_from_slice(key).map_err(|_| {
                        UtilError::InvalidHmacKey {
                            alg: *self,
                            expected: hmac::SimpleHmac::<sha2::Sha256>::key_size(),
                            actual: key.len(),
                        }
                    })?;
                for input in inputs {
                    mac.update(input);
                }

                Ok(mac.verify_slice(tag).is_ok())
            }
            HashAlg::Sha384 => {
                let mut mac =
                    <hmac::SimpleHmac<sha2::Sha384> as hmac::digest::KeyInit>::new_from_slice(key).map_err(|_| {
                        UtilError::InvalidHmacKey {
                            alg: *self,
                            expected: hmac::SimpleHmac::<sha2::Sha384>::key_size(),
                            actual: key.len(),
                        }
                    })?;
                for input in inputs {
                    mac.update(input);
                }

                Ok(mac.verify_slice(tag).is_ok())
            }
            HashAlg::Sha512 => {
                let mut mac =
                    <hmac::SimpleHmac<sha2::Sha512> as hmac::digest::KeyInit>::new_from_slice(key).map_err(|_| {
                        UtilError::InvalidHmacKey {
                            alg: *self,
                            expected: hmac::SimpleHmac::<sha2::Sha512>::key_size(),
                            actual: key.len(),
                        }
                    })?;
                for input in inputs {
                    mac.update(input);
                }

                Ok(mac.verify_slice(tag).is_ok())
            }
        }
    }
}

impl From<CiphersuiteId> for NamedCiphersuite {
    fn from(value: CiphersuiteId) -> Self {
        match *value {
            CiphersuiteId::MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519 => Self::Mls128DHKemX25519AesGcm128Sha256,
            CiphersuiteId::MLS_128_DHKEMP256_AES128GCM_SHA256_P256 => Self::Mls128DHKemP256AesGcm128Sha256,
            CiphersuiteId::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519 => {
                Self::Mls128DHKemX25519ChaCha20Poly1305Sha256
            }
            CiphersuiteId::MLS_256_DHKEMX448_AES256GCM_SHA512_ED448 => Self::Mls256DHKemX448AesGcm256Sha12,
            CiphersuiteId::MLS_256_DHKEMP521_AES256GCM_SHA512_P521 => Self::Mls256DHKemP521AesGcm256Sha512,
            CiphersuiteId::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_ED448 => {
                Self::Mls256DHKemX448ChaCha20Poly1305Sha512
            }
            CiphersuiteId::MLS_256_DHKEMP384_AES256GCM_SHA384_P384 => Self::Mls256DHKemP384AesGcm256Sha384,
            _ => Self::Unknown(value),
        }
    }
}

impl From<NamedCiphersuite> for CiphersuiteId {
    fn from(val: NamedCiphersuite) -> Self {
        match val {
            NamedCiphersuite::Mls128DHKemX25519AesGcm128Sha256 => {
                CiphersuiteId::new_unchecked(CiphersuiteId::MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519)
            }
            NamedCiphersuite::Mls128DHKemP256AesGcm128Sha256 => {
                CiphersuiteId::new_unchecked(CiphersuiteId::MLS_128_DHKEMP256_AES128GCM_SHA256_P256)
            }
            NamedCiphersuite::Mls128DHKemX25519ChaCha20Poly1305Sha256 => {
                CiphersuiteId::new_unchecked(CiphersuiteId::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519)
            }
            NamedCiphersuite::Mls256DHKemX448AesGcm256Sha12 => {
                CiphersuiteId::new_unchecked(CiphersuiteId::MLS_256_DHKEMX448_AES256GCM_SHA512_ED448)
            }
            NamedCiphersuite::Mls256DHKemP521AesGcm256Sha512 => {
                CiphersuiteId::new_unchecked(CiphersuiteId::MLS_256_DHKEMP521_AES256GCM_SHA512_P521)
            }
            NamedCiphersuite::Mls256DHKemX448ChaCha20Poly1305Sha512 => {
                CiphersuiteId::new_unchecked(CiphersuiteId::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_ED448)
            }
            NamedCiphersuite::Mls256DHKemP384AesGcm256Sha384 => {
                CiphersuiteId::new_unchecked(CiphersuiteId::MLS_256_DHKEMP384_AES256GCM_SHA384_P384)
            }
            NamedCiphersuite::Unsupported(value) | NamedCiphersuite::Unknown(value) => value,
        }
    }
}

#[inline]
pub fn encode_mimi_uri(uri: &str) -> String {
    encode_slice(uri.as_bytes())
}

#[inline]
pub fn decode_mimi_uri(encoded: &str) -> Result<String, UtilError> {
    Ok(String::from_utf8(decode_slice(encoded)?)?)
}

pub fn encode_slice(data: &[u8]) -> String {
    bs58::encode(data).with_alphabet(bs58::Alphabet::FLICKR).into_string()
}

pub fn decode_slice(data: &str) -> Result<Vec<u8>, UtilError> {
    Ok(bs58::decode(data).with_alphabet(bs58::Alphabet::FLICKR).into_vec()?)
}

pub fn ref_hash(value: &[u8], label: &str, cs: CiphersuiteId) -> Result<Vec<u8>, UtilError> {
    Ok(NamedCiphersuite::from(cs)
        .hash_alg()?
        .digest(&HashReferenceInput { label, value }.to_tls_bytes()?))
}

const MLS_10_KEYPACKAGE_REF: &str = "MLS 1.0 KeyPackage Reference";
const MLS_10_PROPOSAL_REF: &str = "MLS 1.0 Proposal Reference";

#[inline]
pub fn make_proposal_ref(auth_content: AuthenticatedContentRef, cs: CiphersuiteId) -> Result<Vec<u8>, UtilError> {
    ref_hash(&auth_content.to_tls_bytes()?, MLS_10_PROPOSAL_REF, cs)
}

#[inline]
pub fn make_keypackage_ref(key_package: &KeyPackage) -> Result<Vec<u8>, UtilError> {
    ref_hash(
        &key_package.to_tls_bytes()?,
        MLS_10_KEYPACKAGE_REF,
        key_package.cipher_suite,
    )
}

pub fn extract_group_id_epoch_from_mls_message(message: &MlsMessage) -> Option<(&[u8], &u64)> {
    Some(match &message.content {
        MlsMessageContent::MlsPublicMessage(public_message) => {
            (&public_message.content.group_id, &public_message.content.epoch)
        }
        MlsMessageContent::MlsPrivateMessage(private_message) => (&private_message.group_id, &private_message.epoch),
        MlsMessageContent::GroupInfo(group_info) => {
            (group_info.group_context.group_id(), &group_info.group_context.epoch)
        }
        MlsMessageContent::MlsSemiPrivateMessage(semiprivate_message) => {
            (&semiprivate_message.group_id, &semiprivate_message.epoch)
        }
        MlsMessageContent::Welcome(_) | MlsMessageContent::KeyPackage(_) => return None,
    })
}

pub fn printable_group_id(group_id: &[u8]) -> String {
    GroupId::try_from(group_id)
        .map(|gid| gid.to_string())
        .unwrap_or_else(|_| BASE64_URL_SAFE_NO_PAD.encode(group_id))
}
