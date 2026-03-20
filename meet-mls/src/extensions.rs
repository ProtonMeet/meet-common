use crate::mls_spec;
use mimi_protocol_mls::reexports::mls_spec::group::{ExternalSender, extensions::Extension};
use mls_spec::drafts::mls_extensions::safe_application::ApplicationDataDictionary;

pub trait ExtensionsExt {
    fn app_data(&self) -> Option<&ApplicationDataDictionary>;
    fn external_senders(&self) -> Option<&[ExternalSender]>;
}

impl ExtensionsExt for Vec<Extension> {
    fn app_data(&self) -> Option<&ApplicationDataDictionary> {
        self.iter().find_map(|ext| match ext {
            Extension::ApplicationData(app_data) => Some(app_data),
            _ => None,
        })
    }

    fn external_senders(&self) -> Option<&[ExternalSender]> {
        self.iter().find_map(|ext| match ext {
            Extension::ExternalSenders(ext) => Some(&ext[..]),
            _ => None,
        })
    }
}
