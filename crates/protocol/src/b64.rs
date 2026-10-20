//! Fixed-size byte strings carried as unpadded base64url.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::ProtocolError;

pub fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn decode<const N: usize>(text: &str) -> Result<[u8; N], ProtocolError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|_| ProtocolError::Malformed)?;
    bytes.try_into().map_err(|_| ProtocolError::Malformed)
}

/// Declares a fixed-size byte newtype that serializes as base64url.
///
/// `secret` newtypes print as `<redacted>` in `Debug` so they cannot reach a
/// log through a debug format.
macro_rules! b64_bytes {
    ($(#[$meta:meta])* $name:ident, $len:expr) => {
        $crate::b64::b64_bytes!(@define $(#[$meta])* $name, $len);
        impl ::core::fmt::Debug for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                write!(f, "{}({})", stringify!($name), self.to_b64())
            }
        }
    };
    (secret $(#[$meta:meta])* $name:ident, $len:expr) => {
        $crate::b64::b64_bytes!(@define $(#[$meta])* $name, $len);
        impl ::core::fmt::Debug for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                write!(f, "{}(<redacted>)", stringify!($name))
            }
        }
    };
    (@define $(#[$meta:meta])* $name:ident, $len:expr) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name(pub [u8; $len]);

        impl $name {
            pub const LEN: usize = $len;

            /// Fresh value from `rand::rng()`, a ChaCha CSPRNG seeded from the OS.
            pub fn random() -> Self {
                let mut bytes = [0u8; $len];
                ::rand::RngCore::fill_bytes(&mut ::rand::rng(), &mut bytes);
                Self(bytes)
            }

            pub fn to_b64(self) -> String {
                $crate::b64::encode(&self.0)
            }

            pub fn from_b64(text: &str) -> Result<Self, $crate::ProtocolError> {
                $crate::b64::decode::<$len>(text).map(Self)
            }

            pub fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }
        }

        impl ::serde::Serialize for $name {
            fn serialize<S: ::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(&self.to_b64())
            }
        }

        impl<'de> ::serde::Deserialize<'de> for $name {
            fn deserialize<D: ::serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let text = <::std::borrow::Cow<'de, str> as ::serde::Deserialize>::deserialize(d)?;
                Self::from_b64(&text).map_err(|_| {
                    <D::Error as ::serde::de::Error>::custom(concat!(
                        "invalid ",
                        stringify!($name)
                    ))
                })
            }
        }
    };
}

pub(crate) use b64_bytes;

#[cfg(test)]
mod tests {
    use super::*;

    b64_bytes!(Sample, 4);
    b64_bytes!(secret Hidden, 4);

    #[test]
    fn round_trips_and_rejects_wrong_length() {
        let s = Sample([1, 2, 254, 255]);
        assert_eq!(s.to_b64(), "AQL-_w");
        assert_eq!(Sample::from_b64("AQL-_w"), Ok(s));
        assert_eq!(Sample::from_b64("AQL-"), Err(ProtocolError::Malformed));
        assert_eq!(Sample::from_b64("AQL+/w"), Err(ProtocolError::Malformed));
    }

    #[test]
    fn serializes_as_string_and_redacts_secrets() {
        let json = serde_json::to_string(&Sample([0; 4])).unwrap();
        assert_eq!(json, "\"AAAAAA\"");
        assert_eq!(
            serde_json::from_str::<Sample>(&json).unwrap(),
            Sample([0; 4])
        );
        assert_eq!(format!("{:?}", Hidden([9; 4])), "Hidden(<redacted>)");
    }

    #[test]
    fn random_values_have_the_declared_length_and_differ() {
        let a = Hidden::random();
        assert_eq!(a.as_bytes().len(), Hidden::LEN);
        assert_eq!(Sample::random().as_bytes().len(), Sample::LEN);
        assert_ne!(Sample::random(), Sample::random());
    }
}
