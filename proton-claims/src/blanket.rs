use crate::{
    ProtonClaims, ProtonSdCwtRead,
    reexports::{
        CustomClaims,
        issuance::{SdCwtIssued, SdCwtIssuedTagged},
        key_binding::{KbtCwt, KbtCwtTagged},
    },
};
use esdicawt::SdCwtVerified;

impl<Hasher: digest::Digest + Clone, IssuerProtectedClaims: CustomClaims, IssuerUnprotectedClaims: CustomClaims>
    ProtonSdCwtRead for SdCwtIssued<ProtonClaims, Hasher, IssuerProtectedClaims, IssuerUnprotectedClaims>
{
}

impl<Hasher: digest::Digest + Clone, IssuerProtectedClaims: CustomClaims, IssuerUnprotectedClaims: CustomClaims>
    ProtonSdCwtRead for SdCwtIssuedTagged<ProtonClaims, Hasher, IssuerProtectedClaims, IssuerUnprotectedClaims>
{
}

impl<Hasher: digest::Digest + Clone, IssuerProtectedClaims: CustomClaims, IssuerUnprotectedClaims: CustomClaims>
    ProtonSdCwtRead for SdCwtVerified<ProtonClaims, Hasher, IssuerProtectedClaims, IssuerUnprotectedClaims>
{
}

impl<
    Hasher: digest::Digest + Clone,
    IssuerProtectedClaims: CustomClaims,
    IssuerUnprotectedClaims: CustomClaims,
    KbtProtectedClaims: CustomClaims,
    KbtUnprotectedClaims: CustomClaims,
    KbtPayloadClaims: CustomClaims,
> ProtonSdCwtRead
    for KbtCwt<
        ProtonClaims,
        Hasher,
        IssuerProtectedClaims,
        IssuerUnprotectedClaims,
        KbtProtectedClaims,
        KbtUnprotectedClaims,
        KbtPayloadClaims,
    >
{
}

impl<
    Hasher: digest::Digest + Clone,
    IssuerProtectedClaims: CustomClaims,
    IssuerUnprotectedClaims: CustomClaims,
    KbtProtectedClaims: CustomClaims,
    KbtUnprotectedClaims: CustomClaims,
    KbtPayloadClaims: CustomClaims,
> ProtonSdCwtRead
    for KbtCwtTagged<
        ProtonClaims,
        Hasher,
        IssuerProtectedClaims,
        IssuerUnprotectedClaims,
        KbtProtectedClaims,
        KbtUnprotectedClaims,
        KbtPayloadClaims,
    >
{
}
