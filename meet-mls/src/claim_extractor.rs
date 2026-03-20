use crate::{MeetMlsError, MeetMlsResult, SdKbt, SdKbtVerified, mls_spec};
use meet_policy::SD_CWT_CREDENTIAL_TYPE;
use mimi_room_policy::policy::ClaimExtractor;
use proton_claims::reexports::{CwtAny, Query, SdCwtRead, SpiceOidcSdCwtRead, TokenQuery};
use std::borrow::Cow;

/// Abstraction over an SD-KBT credential
#[derive(Debug)]
pub enum AnySdKbt<'a> {
    Unverified(&'a mut SdKbt),
    #[allow(unused)]
    Verified(&'a mut SdKbtVerified),
}

impl AnySdKbt<'_> {
    pub fn sub(&mut self) -> MeetMlsResult<&str> {
        match self {
            Self::Unverified(sd_kbt) => sd_kbt.sub()?.ok_or(MeetMlsError::InvalidSdCwtCredential),
            Self::Verified(sd_kbt) => sd_kbt
                .sd_cwt()
                .payload
                .subject
                .as_deref()
                .ok_or(MeetMlsError::InvalidSdCwtCredential),
        }
    }

    pub fn email(&mut self) -> Option<Cow<'_, str>> {
        match self {
            Self::Unverified(sd_kbt) => sd_kbt.email().ok().flatten(),
            Self::Verified(sd_kbt) => sd_kbt
                .sd_cwt()
                .payload
                .extra
                .as_ref()?
                .oidc_claims
                .email
                .as_deref()
                .map(Into::into),
        }
    }
}

impl ClaimExtractor for AnySdKbt<'_> {
    fn credential_type(&self) -> mls_spec::defs::CredentialType {
        SD_CWT_CREDENTIAL_TYPE
    }

    // TODO: this method should take &mut for memoizing CBOR deserializations
    fn get_claim(&self, query: &[u8]) -> Option<Vec<u8>> {
        let query: Query = Query::from_cbor_bytes(query).ok()?;
        match &query[..] {
            _ => {
                // look for the claim in the SD-CWT (well technically in its payload or disclosures)
                match self {
                    Self::Unverified(sd_kbt) => (*sd_kbt).clone().query(query).ok()?.to_cbor_bytes().ok(),
                    Self::Verified(sd_kbt) => (*sd_kbt).clone().query(query).ok()?.to_cbor_bytes().ok(),
                }
            }
        }
    }
}
