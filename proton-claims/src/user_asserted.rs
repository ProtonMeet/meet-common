use crate::{ciborium, reexports::Value};
use serde::ser::SerializeMap;

#[derive(
    Debug,
    Copy,
    Clone,
    serde_repr::Serialize_repr,
    serde_repr::Deserialize_repr,
    enum_variants_strings::EnumVariantsStrings,
)]
#[enum_variants_strings_transform(transform = "snake_case")]
#[repr(i64)]
pub enum KbtProtonLabel {
    About = -70000,
}
esdicawt::cwt_label!(KbtProtonLabel);

/// All the claims asserted by a user but not verified by the Authorization server
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct UserAsserted {
    pub about: Option<crate::About>,
}

impl serde::Serialize for UserAsserted {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let len = self.about.as_ref().map(|_| 1).unwrap_or_default();
        let mut map = serializer.serialize_map(Some(len))?;

        if let Some(about) = &self.about {
            map.serialize_entry("about", about)?;
            // TODO: move to this once every client has got this version
            // map.serialize_entry(&KbtProtonLabel::About, about)?;
        }

        map.end()
    }
}

impl<'de> serde::Deserialize<'de> for UserAsserted {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct UserAssertedVisitor;

        impl<'de> serde::de::Visitor<'de> for UserAssertedVisitor {
            type Value = UserAsserted;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "an Proton user asserted payload")
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                use serde::de::Error as _;

                let mut builder = UserAsserted::default();
                while let Some((k, v)) = map.next_entry::<Value, Value>()? {
                    match (k, v) {
                        (Value::Integer(i), about) if i == KbtProtonLabel::About => {
                            let about = about.deserialized::<Option<crate::About>>().map_err(A::Error::custom)?;
                            builder.about = about;
                        }
                        // compatibility layer for legacy
                        (Value::Text(i), about) if i == "about" => {
                            let about = about.deserialized::<Option<crate::About>>().map_err(A::Error::custom)?;
                            builder.about = about;
                        }
                        _ => {}
                    }
                }

                Ok(builder)
            }
        }

        deserializer.deserialize_map(UserAssertedVisitor)
    }
}
