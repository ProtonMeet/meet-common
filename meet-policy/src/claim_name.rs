use crate::PolicyResult;
use mimi_protocol_mls::reexports::mls_spec::defs::CredentialType;
use mimi_room_policy::spec::preauth::{Claim, ClaimId};
use proton_claims::reexports::{ClaimName, CwtAny, Query, QueryElement};
use proton_claims::{CwtProtonLabel, CwtProtonMeetLabel};

pub trait ClaimNameExt {
    fn preauth_claim_id(&self) -> PolicyResult<ClaimId>;
    fn preauth_claim_condition<V: CwtAny>(&self, value: &V) -> PolicyResult<Claim>;
}

pub const SD_CWT_CREDENTIAL_TYPE: CredentialType = CredentialType::new_unchecked(CredentialType::SD_CWT_CREDENTIAL);

impl ClaimNameExt for ClaimName {
    fn preauth_claim_id(&self) -> PolicyResult<ClaimId> {
        let elements = vec![QueryElement::ClaimName(self.clone())];
        let id = Query::from(elements).to_cbor_bytes()?;
        Ok(ClaimId {
            credential_type: SD_CWT_CREDENTIAL_TYPE,
            id,
        })
    }

    fn preauth_claim_condition<V: CwtAny>(&self, value: &V) -> PolicyResult<Claim> {
        Ok(Claim {
            claim_id: self.preauth_claim_id()?,
            claim_value: value.to_cbor_bytes()?,
        })
    }
}

impl ClaimNameExt for CwtProtonLabel {
    fn preauth_claim_id(&self) -> PolicyResult<ClaimId> {
        ClaimName::from(*self).preauth_claim_id()
    }

    fn preauth_claim_condition<V: CwtAny>(&self, value: &V) -> PolicyResult<Claim> {
        ClaimName::from(*self).preauth_claim_condition(value)
    }
}

impl ClaimNameExt for proton_claims::reexports::CwtOidcLabel {
    fn preauth_claim_id(&self) -> PolicyResult<ClaimId> {
        ClaimName::from(*self).preauth_claim_id()
    }

    fn preauth_claim_condition<V: CwtAny>(&self, value: &V) -> PolicyResult<Claim> {
        ClaimName::from(*self).preauth_claim_condition(value)
    }
}

impl ClaimNameExt for CwtProtonMeetLabel {
    fn preauth_claim_id(&self) -> PolicyResult<ClaimId> {
        ClaimName::from(*self).preauth_claim_id()
    }

    fn preauth_claim_condition<V: CwtAny>(&self, value: &V) -> PolicyResult<Claim> {
        ClaimName::from(*self).preauth_claim_condition(value)
    }
}
