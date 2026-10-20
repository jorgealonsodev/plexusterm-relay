//! Identifiers, link secrets and the keys derived from them.
//!
//! Each link secret is expanded with HKDF-SHA-256 into three independent
//! values: a public `link_id`, the Noise PSK and `relay_auth`. The relay only
//! ever sees `link_id` and `verifier = SHA-256(relay_auth)`, and a joining
//! party proves knowledge of the secret with `HMAC(verifier, challenge…)`.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::b64::b64_bytes;

b64_bytes!(
    /// 128-bit random share identifier, the path segment of a link.
    ShareId,
    16
);
b64_bytes!(
    /// Public identifier of one link of a share, derived from its secret.
    LinkId,
    16
);
b64_bytes!(
    /// SHA-256 of `relay_auth`; the only link material the relay stores.
    Verifier,
    32
);
b64_bytes!(
    /// 256-bit random nonce the relay sends before any proof.
    Challenge,
    32
);
b64_bytes!(
    /// HMAC proof of knowledge of a link or owner secret.
    Proof,
    32
);
b64_bytes!(secret
    /// 256-bit link or owner secret. Travels only in a link's `#` fragment
    /// or stays on the sharing side.
    Secret,
    32
);

const HKDF_SALT: &[u8] = b"plexusterm-share v1";
const PROOF_LABEL: &[u8] = b"plexusterm-share v1 proof";

impl ShareId {
    /// Short non-reversible tag for operational logs (PRD §6.2: logs hold
    /// share id hashes, never share ids).
    pub fn log_tag(&self) -> String {
        let digest = Sha256::digest(self.0);
        digest[..6].iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// Who is proving knowledge of a secret. Bound into the proof so a viewer
/// proof can never be replayed as an owner proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Viewer = 1,
    Owner = 2,
}

/// Everything a holder of a secret derives from it.
#[derive(Clone)]
pub struct DerivedKeys {
    pub link_id: LinkId,
    pub psk: [u8; 32],
    relay_auth: [u8; 32],
}

impl core::fmt::Debug for DerivedKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DerivedKeys")
            .field("link_id", &self.link_id)
            .finish_non_exhaustive()
    }
}

impl DerivedKeys {
    pub fn derive(secret: &Secret) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), &secret.0);
        let mut link_id = [0u8; 16];
        let mut psk = [0u8; 32];
        let mut relay_auth = [0u8; 32];
        // HKDF-SHA-256 can expand up to 255 * 32 bytes; these lengths are
        // constants far below that, so expand cannot fail.
        for (info, out) in [
            (&b"link id"[..], &mut link_id[..]),
            (&b"handshake psk"[..], &mut psk[..]),
            (&b"relay auth"[..], &mut relay_auth[..]),
        ] {
            hk.expand(info, out)
                .unwrap_or_else(|_| unreachable!("constant HKDF length"));
        }
        Self {
            link_id: LinkId(link_id),
            psk,
            relay_auth,
        }
    }

    pub fn verifier(&self) -> Verifier {
        Verifier(Sha256::digest(self.relay_auth).into())
    }

    pub fn prove(&self, role: Role, share_id: &ShareId, challenge: &Challenge) -> Proof {
        let mac = proof_mac(&self.verifier(), role, share_id, challenge);
        Proof(mac.finalize().into_bytes().into())
    }
}

impl Verifier {
    /// Constant-time check of a proof against this verifier.
    pub fn check(
        &self,
        role: Role,
        share_id: &ShareId,
        challenge: &Challenge,
        proof: &Proof,
    ) -> bool {
        proof_mac(self, role, share_id, challenge)
            .verify_slice(&proof.0)
            .is_ok()
    }
}

fn proof_mac(
    verifier: &Verifier,
    role: Role,
    share_id: &ShareId,
    challenge: &Challenge,
) -> Hmac<Sha256> {
    // HMAC accepts keys of any length, so construction cannot fail.
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&verifier.0)
        .unwrap_or_else(|_| unreachable!("HMAC takes any key length"));
    mac.update(PROOF_LABEL);
    mac.update(&[role as u8]);
    mac.update(&share_id.0);
    mac.update(&challenge.0);
    mac
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_is_deterministic_and_separates_outputs() {
        let secret = Secret([7; 32]);
        let a = DerivedKeys::derive(&secret);
        let b = DerivedKeys::derive(&secret);
        assert_eq!(a.link_id, b.link_id);
        assert_eq!(a.psk, b.psk);
        assert_ne!(a.psk, a.relay_auth);
        assert_ne!(&a.psk[..16], &a.link_id.0[..]);
        let other = DerivedKeys::derive(&Secret([8; 32]));
        assert_ne!(a.link_id, other.link_id);
        assert_ne!(a.verifier(), other.verifier());
    }

    #[test]
    fn proof_checks_only_with_matching_inputs() {
        let keys = DerivedKeys::derive(&Secret([1; 32]));
        let share = ShareId([2; 16]);
        let challenge = Challenge([3; 32]);
        let proof = keys.prove(Role::Viewer, &share, &challenge);
        let verifier = keys.verifier();
        assert!(verifier.check(Role::Viewer, &share, &challenge, &proof));
        assert!(!verifier.check(Role::Owner, &share, &challenge, &proof));
        assert!(!verifier.check(Role::Viewer, &ShareId([9; 16]), &challenge, &proof));
        assert!(!verifier.check(Role::Viewer, &share, &Challenge([4; 32]), &proof));
        let wrong = DerivedKeys::derive(&Secret([5; 32])).verifier();
        assert!(!wrong.check(Role::Viewer, &share, &challenge, &proof));
    }

    #[test]
    fn log_tag_is_short_and_not_the_id() {
        let id = ShareId([0xab; 16]);
        let tag = id.log_tag();
        assert_eq!(tag.len(), 12);
        assert!(!id.to_b64().contains(&tag));
        assert_eq!(format!("{:?}", Secret([1; 32])), "Secret(<redacted>)");
    }
}
