use mimi_protocol_mls::reexports::mls_spec::{
    AuthenticationServiceDelegate, Serializable as _, ToPrefixedLabel,
    defs::{CiphersuiteId, ProtocolVersion, labels::SignatureLabel},
    key_package::KeyPackage,
    tree::leaf_node::LeafNodeSource,
};

use super::leaf_node::LeafNodeValidationContext;
use crate::{
    UtilError,
    validations::{InvalidSignatureItem, ValidationError},
};

#[derive(Debug, Default, Clone, Copy)]
pub struct KeyPackageValidationContext {
    /// Time at which to perform the validation.
    /// This is useful to validate operations at the time they occur retroactively
    /// If this is `None` then no time validations are performed
    pub time: Option<u64>,
    /// Acceptable range of lifetime of keypackages
    pub acceptable_range: Option<u64>,
    /// Ciphersuite of the validation
    pub cipher_suite: Option<CiphersuiteId>,
}

impl KeyPackageValidationContext {
    pub fn at(time: u64) -> Self {
        Self {
            time: Some(time),
            acceptable_range: None,
            cipher_suite: None,
        }
    }

    pub fn with_ciphersuite(mut self, ciphersuite: CiphersuiteId) -> Self {
        self.cipher_suite.replace(ciphersuite);
        self
    }

    /// Validates if the keypackage satisfies both a current timestamp (seconds since UNIX epoch) & a provided breadth of not_before/not_after
    pub fn validate_keypackage_lifetime(&self, leaf_node_source: &LeafNodeSource) -> bool {
        const LIFETIME_WIGGLE_ROOM: u64 = 50_400; // 14h wiggle woom for non-NTP synced clients

        let LeafNodeSource::KeyPackage { lifetime } = &leaf_node_source else {
            return false;
        };

        if lifetime.not_after < lifetime.not_before {
            return false;
        }

        if let Some(acceptable_range) = self.acceptable_range {
            let kp_range = lifetime.not_after.saturating_sub(lifetime.not_before);
            if kp_range > acceptable_range {
                return false;
            }
        }

        let Some(time) = self.time else {
            // If time isn't set, skip the nbf/naf validations
            return true;
        };

        // Add some wiggle room
        let nbf = lifetime.not_before.saturating_sub(LIFETIME_WIGGLE_ROOM);
        let naf = lifetime.not_after.saturating_add(LIFETIME_WIGGLE_ROOM);

        nbf < time && time < naf
    }

    /// https://www.rfc-editor.org/rfc/rfc9420.html#name-keypackage-validation
    pub async fn validate(
        &self,
        key_package: &KeyPackage,
        credential_validator: &dyn AuthenticationServiceDelegate,
    ) -> Result<(), UtilError> {
        // Verify that the ciphersuite and protocol version of the KeyPackage match those in the GroupContext.
        if key_package.version != ProtocolVersion::Mls10 {
            return Err(ValidationError::WtfIsThisProtocol.into());
        }

        let Some(ciphersuite) = self.cipher_suite else {
            return Err(ValidationError::NoCiphersuite.into());
        };

        if key_package.cipher_suite != ciphersuite {
            return Err(ValidationError::CiphersuiteMismatch.into());
        }

        // Verify that the leaf_node of the KeyPackage is valid for a KeyPackage according to Section 7.3.
        LeafNodeValidationContext::KeyPackage(self)
            .validate_leaf_node(&key_package.leaf_node, credential_validator)
            .await?;

        // Verify that the signature on the KeyPackage is valid using the public key in leaf_node.credential.
        crate::crypto::signatures::verify_with_label(
            &key_package.leaf_node.signature_key,
            ciphersuite,
            &key_package.to_tbs().to_tls_bytes()?,
            &SignatureLabel::KeyPackageTBS.to_prefixed_string(key_package.version),
            &key_package.signature,
        )
        .map_err(|_| ValidationError::InvalidSignature(InvalidSignatureItem::KeyPackage))?;

        // Verify that the value of leaf_node.encryption_key is different from the value of the init_key field.
        if key_package.init_key == key_package.leaf_node.encryption_key {
            return Err(ValidationError::LeafNodeEncryptionKeyIsKeyPackageInitKey.into());
        }

        Ok(())
    }
}
