use mimi_protocol_mls::reexports::mls_spec::{MlsSpecError, drafts::mls_extensions::safe_application::ComponentId};

#[derive(Debug, thiserror::Error)]
pub enum MeetAppComponentsError {
    #[error(transparent)]
    MlsSpecError(#[from] MlsSpecError),
    #[error("Cannot update component with ID {0}")]
    UnsupportedComponentUpdate(ComponentId),
}
