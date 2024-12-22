//! Symmetric-Key Encrypted Session Key Packets.
//!
//! SKESK packets hold symmetrically encrypted session keys.  The
//! session key is needed to decrypt the actual ciphertext.  See
//! [Section 5.3 of RFC 4880] for details.
//!
//! [Section 5.3 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.3

#[cfg(test)]
use quickcheck::{Arbitrary, Gen};

use crate::Result;
use crate::crypto::{
    Password,
    SessionKey,
};

use crate::types::{
    SymmetricAlgorithm,
};
use crate::Packet;

mod v4;
pub use v4::SKESK4;
mod v6;
pub use v6::SKESK6;

/// Holds a symmetrically encrypted session key.
///
/// The session key is used to decrypt the actual ciphertext, which is
/// typically stored in a [SEIP] packet.  See [Section 5.3 of RFC
/// 4880] for details.
///
/// An SKESK packet is not normally instantiated directly.  In most
/// cases, you'll create one as a side-effect of encrypting a message
/// using the [streaming serializer], or parsing an encrypted message
/// using the [`PacketParser`].
///
/// Note: This enum cannot be exhaustively matched to allow future
/// extensions.
///
/// [SEIP]: crate::packet::SEIP
/// [Section 5.3 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.3
/// [streaming serializer]: crate::serialize::stream
/// [`PacketParser`]: crate::parse::PacketParser
#[non_exhaustive]
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub enum SKESK {
    /// SKESK packet version 4.
    V4(self::SKESK4),

    /// SKESK packet version 6.
    V6(self::SKESK6),
}
assert_send_and_sync!(SKESK);

impl SKESK {
    /// Gets the version.
    pub fn version(&self) -> u8 {
        match self {
            SKESK::V4(_) => 4,
            SKESK::V6(_) => 6,
        }
    }

    /// Derives the key inside this SKESK from `password`. Returns a
    /// tuple of the symmetric cipher to use with the key and the key
    /// itself.
    pub fn decrypt(&self, password: &Password)
        -> Result<(SymmetricAlgorithm, SessionKey)>
    {
        match self {
            SKESK::V4(ref s) => s.decrypt(password),
            SKESK::V6(ref s) =>
                Ok((SymmetricAlgorithm::Unencrypted, s.decrypt(password)?)),
        }
    }
}

impl From<SKESK> for Packet {
    fn from(p: SKESK) -> Self {
        Packet::SKESK(p)
    }
}

#[cfg(test)]
impl Arbitrary for SKESK {
    fn arbitrary(g: &mut Gen) -> Self {
        if bool::arbitrary(g) {
            SKESK::V4(SKESK4::arbitrary(g))
        } else {
            SKESK::V6(SKESK6::arbitrary(g))
        }
    }
}
