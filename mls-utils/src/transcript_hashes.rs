use mimi_protocol_mls::reexports::mls_spec::{
    SensitiveBytes, Serializable,
    defs::WireFormat,
    key_schedule::{ConfirmedTranscriptHashInput, GroupContext, InterimTranscriptHashInput},
    messages::{ContentType, ContentTypeInner, MlsMessage},
};

use crate::{NamedCiphersuite, UtilError};

pub fn compute_confirmed_transcript_hash_from_commit_message(
    interim_transcript_hash_n_1: &[u8],
    message: &MlsMessage,
    ctx: &GroupContext,
) -> Result<SensitiveBytes, UtilError> {
    let ct = message
        .content
        .content_type()
        .ok_or(UtilError::InvalidOrMissingContentType)?;

    if ct != ContentType::Commit {
        return Err(UtilError::InvalidOrMissingContentType);
    }

    let wire_format;
    let content;
    let signature;
    match &message.content {
        mimi_protocol_mls::reexports::mls_spec::messages::MlsMessageContent::MlsPublicMessage(public_message) => {
            wire_format = WireFormat::new_unchecked(WireFormat::MLS_PUBLIC_MESSAGE);
            content = &public_message.content;
            signature = &public_message.auth.signature;
        }
        mimi_protocol_mls::reexports::mls_spec::messages::MlsMessageContent::MlsSemiPrivateMessage(
            _semi_private_message,
        ) => {
            wire_format = WireFormat::new_unchecked(WireFormat::MLS_SEMIPRIVATE_MESSAGE);
            // TODO: Decrypt that stuff
            return Err(UtilError::UnsupportedWireFormat(wire_format));
        }
        _ => return Err(UtilError::InvalidOrMissingContentType),
    }

    compute_confirmed_transcript_hash(
        interim_transcript_hash_n_1,
        ConfirmedTranscriptHashInput {
            wire_format: &wire_format,
            content,
            signature,
        },
        ctx,
    )
}

pub fn compute_confirmed_transcript_hash(
    interim_transcript_hash_n_1: &[u8],
    input: ConfirmedTranscriptHashInput,
    ctx: &GroupContext,
) -> Result<SensitiveBytes, UtilError> {
    if ctx.epoch == 0 {
        return Ok(Default::default());
    }

    if !matches!(input.content.content, ContentTypeInner::Commit { .. }) {
        return Err(UtilError::ApiMisuse(
            "Tried to compute the confirmed transcript hash on not a commit",
        ));
    }

    Ok(NamedCiphersuite::from(ctx.cipher_suite)
        .hash_alg()?
        .digest_multi(&[interim_transcript_hash_n_1, &input.to_tls_bytes()?])
        .into())
}

pub fn compute_interim_transcript_hash(
    confirmed_transcript_hash: &[u8],
    input: InterimTranscriptHashInput,
    ctx: &GroupContext,
) -> Result<SensitiveBytes, UtilError> {
    Ok(NamedCiphersuite::from(ctx.cipher_suite)
        .hash_alg()?
        .digest_multi(&[confirmed_transcript_hash, &input.to_tls_bytes()?])
        .into())
}
